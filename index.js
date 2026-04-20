#!/usr/bin/env node

import { writeFileSync, mkdirSync, existsSync, readFileSync, promises as fsPromises } from 'fs';
import { join, resolve } from 'path';
import { gzipSync, brotliCompressSync } from 'zlib';
import crypto from 'crypto';
import { Mutex } from 'async-mutex';
import pino from 'pino';
import axios, { AxiosInstance, AxiosError } from 'axios';
import { BloomFilter } from 'bloom-filters';
import dns from 'dns';
import { promisify } from 'util';
import os from 'os';

// ============================================================================
// CONSTANTS
// ============================================================================

const MIN_DOMAIN_LENGTH = 3;
const MAX_DOMAIN_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
const DEFAULT_BUFFER_SIZE = 256 * 1024;
const MAX_RESPONSE_SIZE_MB = 100;
const MAX_RESPONSE_SIZE_BYTES = MAX_RESPONSE_SIZE_MB * 1024 * 1024;
const DECOMPRESSION_RATIO_LIMIT = 10;
const MAX_DECOMPRESSED_SIZE = MAX_RESPONSE_SIZE_BYTES * DECOMPRESSION_RATIO_LIMIT;
const DEFAULT_RETRY_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 1000;
const RETRY_MAX_DELAY_MS = 30000;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5;
const CIRCUIT_BREAKER_TIMEOUT_MS = 60000;
const GRACEFUL_SHUTDOWN_TIMEOUT_MS = 30000;
const WORKER_COUNT = Math.max(1, Math.min(os.cpus().length, 8));

// ============================================================================
// INTERFACES
// ============================================================================

interface Logger {
    debug(msg: string, args?: Record<string, unknown>): void;
    info(msg: string, args?: Record<string, unknown>): void;
    warn(msg: string, args?: Record<string, unknown>): void;
    error(msg: string, err?: Error, args?: Record<string, unknown>): void;
}

interface Metrics {
    recordDuration(name: string, durationMs: number, labels?: Record<string, string>): void;
    recordCounter(name: string, value: number, labels?: Record<string, string>): void;
    recordGauge(name: string, value: number, labels?: Record<string, string>): void;
}

interface SourceConfig {
    name: string;
    url: string;
    enabled: boolean;
    timeout?: number;
    retries?: number;
}

interface ValidationContext {
    maxLabels: number;
    blockPunycode: boolean;
    maxRiskScore: number;
}

interface DomainMetadata {
    domain: string;
    source: string;
    firstSeen: number;
    occurrences: number;
}

interface BuildResult {
    success: boolean;
    duration?: number;
    domainCount?: number;
    outputPath?: string;
    error?: string;
    timestamp: string;
}

interface DedupStats {
    uniqueDomains: number;
    totalProcessed: number;
    duplicateRate: number;
}

interface ProcessResult {
    domains: string[];
    stats: DedupStats;
}

interface FetchResult {
    data: string;
    sourceName: string;
    fetchTimeMs: number;
    cached: boolean;
}

// ============================================================================
// NOOP IMPLEMENTATIONS FOR TESTING
// ============================================================================

class NoopLogger implements Logger {
    debug(_msg: string, _args?: Record<string, unknown>): void {}
    info(_msg: string, _args?: Record<string, unknown>): void {}
    warn(_msg: string, _args?: Record<string, unknown>): void {}
    error(_msg: string, _err?: Error, _args?: Record<string, unknown>): void {}
}

class NoopMetrics implements Metrics {
    recordDuration(_name: string, _durationMs: number, _labels?: Record<string, string>): void {}
    recordCounter(_name: string, _value: number, _labels?: Record<string, string>): void {}
    recordGauge(_name: string, _value: number, _labels?: Record<string, string>): void {}
}

// ============================================================================
// CIRCUIT BREAKER
// ============================================================================

class CircuitBreaker {
    private failures = 0;
    private lastFailureTime = 0;
    private state: 'closed' | 'open' | 'half-open' = 'closed';
    private readonly failureThreshold: number;
    private readonly timeoutMs: number;

    constructor(failureThreshold: number = CIRCUIT_BREAKER_FAILURE_THRESHOLD, timeoutMs: number = CIRCUIT_BREAKER_TIMEOUT_MS) {
        this.failureThreshold = failureThreshold;
        this.timeoutMs = timeoutMs;
    }

    async execute<T>(fn: () => Promise<T>): Promise<T> {
        if (this.state === 'open') {
            if (Date.now() - this.lastFailureTime > this.timeoutMs) {
                this.state = 'half-open';
            } else {
                throw new Error('Circuit breaker is open');
            }
        }

        try {
            const result = await fn();
            if (this.state === 'half-open') {
                this.reset();
            }
            return result;
        } catch (error) {
            this.recordFailure();
            throw error;
        }
    }

    private recordFailure(): void {
        this.failures++;
        this.lastFailureTime = Date.now();
        if (this.failures >= this.failureThreshold) {
            this.state = 'open';
        }
    }

    private reset(): void {
        this.failures = 0;
        this.state = 'closed';
    }

    getState(): string {
        return this.state;
    }
}

// ============================================================================
// SSRF PROTECTION
// ============================================================================

class SSRFProtector {
    private static readonly PRIVATE_IP_RANGES = [
        /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/,
        /^192\.168\.\d{1,3}\.\d{1,3}$/,
        /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
        /^169\.254\.\d{1,3}\.\d{1,3}$/,
        /^::1$/,
        /^fc00:/,
        /^fe80:/
    ];

    static async validate(url: URL): Promise<void> {
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            throw new Error(`Unsupported protocol: ${url.protocol}`);
        }

        const lookupPromise = promisify(dns.lookup);
        const { address } = await lookupPromise(url.hostname);
        
        for (const pattern of this.PRIVATE_IP_RANGES) {
            if (pattern.test(address)) {
                throw new Error(`Blocked private IP: ${address} for hostname ${url.hostname}`);
            }
        }
    }
}

// ============================================================================
// RETRY WITH EXPONENTIAL BACKOFF
// ============================================================================

class RetryHandler {
    static async withRetry<T>(
        fn: () => Promise<T>,
        maxAttempts: number = DEFAULT_RETRY_ATTEMPTS,
        baseDelayMs: number = RETRY_BASE_DELAY_MS,
        logger?: Logger
    ): Promise<T> {
        let lastError: Error = new Error('Unknown error');
        
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return await fn();
            } catch (error) {
                lastError = error as Error;
                
                if (attempt === maxAttempts) {
                    throw lastError;
                }
                
                const delay = Math.min(baseDelayMs * Math.pow(2, attempt - 1), RETRY_MAX_DELAY_MS);
                const jitter = delay * 0.1 * Math.random();
                
                if (logger) {
                    logger.warn(`Retry attempt ${attempt}/${maxAttempts} after ${delay + jitter}ms`, {
                        error: lastError.message
                    });
                }
                
                await new Promise(resolve => setTimeout(resolve, delay + jitter));
            }
        }
        
        throw lastError;
    }
}

// ============================================================================
// FETCH MANAGER WITH RETRY, CIRCUIT BREAKER & SSRF PROTECTION
// ============================================================================

class FetchManager {
    private axiosInstance: AxiosInstance;
    private logger: Logger;
    private metrics: Metrics;
    private circuitBreaker: CircuitBreaker;
    private cacheDir: string;
    private readonly cacheTTLMs: number = 86400000;

    constructor(logger: Logger, metrics: Metrics, cacheDir: string = './cache') {
        this.logger = logger;
        this.metrics = metrics;
        this.circuitBreaker = new CircuitBreaker();
        this.cacheDir = cacheDir;
        
        this.axiosInstance = axios.create({
            timeout: 30000,
            maxRedirects: 5,
            maxContentLength: MAX_RESPONSE_SIZE_BYTES,
            validateStatus: (status) => status === 200,
            headers: {
                'User-Agent': 'DNS-Blocklist-Builder/6.0',
                'Accept': 'text/plain, text/html',
                'Accept-Encoding': 'gzip, deflate',
            },
        });
        
        mkdirSync(cacheDir, { recursive: true });
    }

    private getCachePath(url: string): string {
        const hash = crypto.createHash('sha256').update(url).digest('hex');
        return join(this.cacheDir, `${hash}.cache`);
    }

    private async readFromCache(url: string): Promise<string | null> {
        try {
            const cachePath = this.getCachePath(url);
            const stats = await fsPromises.stat(cachePath);
            
            if (Date.now() - stats.mtimeMs > this.cacheTTLMs) {
                return null;
            }
            
            return await fsPromises.readFile(cachePath, 'utf8');
        } catch {
            return null;
        }
    }

    private async writeToCache(url: string, data: string): Promise<void> {
        try {
            const cachePath = this.getCachePath(url);
            await fsPromises.writeFile(cachePath, data, 'utf8');
        } catch (error) {
            this.logger.warn('Failed to write cache', { url, error: (error as Error).message });
        }
    }

    async fetch(url: string, sourceName: string, timeout?: number): Promise<FetchResult> {
        const startTime = Date.now();
        const urlObj = new URL(url);
        
        await SSRFProtector.validate(urlObj);
        
        const cached = await this.readFromCache(url);
        if (cached) {
            this.metrics.recordCounter('fetch.cache_hit', 1, { source: sourceName });
            return {
                data: cached,
                sourceName,
                fetchTimeMs: 0,
                cached: true
            };
        }
        
        try {
            const result = await RetryHandler.withRetry(async () => {
                return await this.circuitBreaker.execute(async () => {
                    const response = await this.axiosInstance.get(url, {
                        timeout: timeout || 30000,
                        signal: AbortSignal.timeout(timeout || 30000),
                    });
                    
                    if (response.data.length > MAX_RESPONSE_SIZE_BYTES) {
                        throw new Error(`Response too large: ${response.data.length} bytes`);
                    }
                    
                    return response;
                });
            }, 3, RETRY_BASE_DELAY_MS, this.logger);
            
            const fetchTimeMs = Date.now() - startTime;
            
            await this.writeToCache(url, result.data);
            
            this.metrics.recordDuration('fetch.duration', fetchTimeMs, { source: sourceName });
            this.metrics.recordCounter('fetch.bytes', result.data.length, { source: sourceName });
            
            return {
                data: result.data,
                sourceName,
                fetchTimeMs,
                cached: false
            };
        } catch (error) {
            this.metrics.recordCounter('fetch.errors', 1, { source: sourceName, error: (error as Error).message });
            
            const fallback = await this.readFromCache(url);
            if (fallback) {
                this.logger.warn(`Using cached fallback for ${sourceName}`, { error: (error as Error).message });
                return {
                    data: fallback,
                    sourceName,
                    fetchTimeMs: 0,
                    cached: true
                };
            }
            
            throw new Error(`Failed to fetch ${sourceName}: ${(error as Error).message}`);
        }
    }
}

// ============================================================================
// DOMAIN VALIDATOR
// ============================================================================

class DomainValidator {
    private static readonly DOMAIN_REGEX = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i;
    private static readonly CONFUSABLE_MAP = new Map<string, string>([
        ['а', 'a'], ['е', 'e'], ['о', 'o'], ['р', 'p'], ['с', 'c'],
        ['х', 'x'], ['у', 'y'], ['к', 'k'], ['в', 'b'], ['н', 'h']
    ]);

    validate(domain: string, context: ValidationContext): { isValid: boolean; normalized: string | null; riskScore: number } {
        if (!domain || typeof domain !== 'string') {
            return { isValid: false, normalized: null, riskScore: 100 };
        }

        let normalized = domain.normalize('NFKC').toLowerCase().trim();
        
        if (normalized.endsWith('.')) {
            normalized = normalized.slice(0, -1);
        }

        if (normalized.length < MIN_DOMAIN_LENGTH || normalized.length > MAX_DOMAIN_LENGTH) {
            return { isValid: false, normalized: null, riskScore: 100 };
        }

        if (context.blockPunycode && normalized.startsWith('xn--')) {
            return { isValid: false, normalized: null, riskScore: 100 };
        }

        const labels = normalized.split('.');
        if (labels.length > context.maxLabels) {
            return { isValid: false, normalized: null, riskScore: 100 };
        }

        let riskScore = 0;
        
        for (const label of labels) {
            if (label.length === 0 || label.length > MAX_LABEL_LENGTH) {
                return { isValid: false, normalized: null, riskScore: 100 };
            }
            
            if (label.startsWith('-') || label.endsWith('-')) {
                return { isValid: false, normalized: null, riskScore: 100 };
            }
            
            if (!DomainValidator.DOMAIN_REGEX.test(label)) {
                return { isValid: false, normalized: null, riskScore: 100 };
            }
            
            if (this.hasConfusableCharacters(label)) {
                riskScore += 20;
            }
        }

        const isValid = riskScore < context.maxRiskScore;
        return { isValid, normalized: isValid ? normalized : null, riskScore };
    }

    private hasConfusableCharacters(label: string): boolean {
        for (const [confusable] of DomainValidator.CONFUSABLE_MAP) {
            if (label.includes(confusable)) return true;
        }
        return false;
    }
}

// ============================================================================
// DEDUPLICATION ENGINE WITH LRU
// ============================================================================

class DeduplicationEngine {
    private domains: Map<string, DomainMetadata> = new Map();
    private bloomFilter: BloomFilter;
    private mutex = new Mutex();
    private readonly maxSize: number;
    private totalProcessed = 0;

    constructor(expectedSize: number = 5000000, maxSize: number = 10000000) {
        this.bloomFilter = new BloomFilter(expectedSize, 0.01);
        this.maxSize = maxSize;
    }

    private evictOldest(): void {
        if (this.domains.size <= this.maxSize) return;
        
        const entries = Array.from(this.domains.entries());
        entries.sort((a, b) => a[1].firstSeen - b[1].firstSeen);
        
        const toRemove = entries.slice(0, this.domains.size - this.maxSize);
        for (const [domain] of toRemove) {
            this.domains.delete(domain);
        }
    }

    async add(domain: string, source: string): Promise<boolean> {
        const release = await this.mutex.acquire();
        
        try {
            this.totalProcessed++;
            this.evictOldest();
            
            if (this.bloomFilter.has(domain)) {
                const existing = this.domains.get(domain);
                if (existing) {
                    existing.occurrences++;
                    return false;
                }
            }
            
            if (!this.domains.has(domain)) {
                this.domains.set(domain, {
                    domain,
                    source,
                    firstSeen: Date.now(),
                    occurrences: 1,
                });
                this.bloomFilter.add(domain);
                return true;
            }
            
            return false;
        } finally {
            release();
        }
    }

    getAll(): string[] {
        return Array.from(this.domains.keys()).sort();
    }

    getStats(): DedupStats {
        return {
            uniqueDomains: this.domains.size,
            totalProcessed: this.totalProcessed,
            duplicateRate: this.totalProcessed > 0 ? (1 - this.domains.size / this.totalProcessed) * 100 : 0,
        };
    }
}

// ============================================================================
// OUTPUT GENERATOR
// ============================================================================

class OutputGenerator {
    private static readonly VERSION = '6.0.0';

    static generate(domains: string[], format: 'hosts' | 'domains'): string {
        const header = this.generateHeader(domains.length);
        let content = header;
        
        if (format === 'hosts') {
            const batchSize = 10000;
            for (let i = 0; i < domains.length; i += batchSize) {
                const batch = domains.slice(i, i + batchSize);
                for (const domain of batch) {
                    content += `0.0.0.0 ${domain}\n`;
                    content += `:: ${domain}\n`;
                }
            }
        } else {
            content += domains.join('\n');
        }
        
        return content;
    }

    private static generateHeader(domainCount: number): string {
        const now = new Date().toISOString();
        return `# DNS Blocklist v${this.VERSION}
# Generated: ${now}
# Total Domains: ${domainCount.toLocaleString()}
# ============================================================================
# END OF HEADER
# ============================================================================

`;
    }

    static async write(content: string, outputDir: string, format: string, timeoutMs: number = 30000): Promise<string> {
        const outputPath = resolve(outputDir, `blocklist.${format === 'hosts' ? 'txt' : 'domains'}`);
        mkdirSync(outputDir, { recursive: true });
        
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        
        try {
            await fsPromises.writeFile(outputPath, content, { signal: controller.signal as any });
            const gzipPath = `${outputPath}.gz`;
            await fsPromises.writeFile(gzipPath, gzipSync(content, { level: 9 }));
            
            return outputPath;
        } finally {
            clearTimeout(timeout);
        }
    }
}

// ============================================================================
// DOMAIN PARSER WITH WORKER POOL
// ============================================================================

class DomainParser {
    private static readonly HOSTS_IPS = new Set(['0.0.0.0', '127.0.0.1', '::1', '0']);
    
    static parse(content: string): string[] {
        const domains: string[] = [];
        const lines = content.split(/\r?\n/);
        
        for (const line of lines) {
            const trimmed = line.trim();
            
            if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) {
                continue;
            }
            
            const parts = trimmed.split(/\s+/);
            
            if (parts.length >= 2 && DomainParser.HOSTS_IPS.has(parts[0])) {
                const domain = parts[1].toLowerCase();
                if (DomainParser.isValidDomainFormat(domain)) {
                    domains.push(domain);
                }
            } else if (DomainParser.isValidDomainFormat(trimmed)) {
                domains.push(trimmed.toLowerCase());
            }
        }
        
        return domains;
    }
    
    private static isValidDomainFormat(domain: string): boolean {
        return /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i.test(domain) && domain.length <= MAX_DOMAIN_LENGTH;
    }
}

// ============================================================================
// MAIN BUILDER
// ============================================================================

class BlocklistBuilder {
    private validator: DomainValidator;
    private fetcher: FetchManager;
    private dedupEngine: DeduplicationEngine;
    private logger: Logger;
    private metrics: Metrics;
    private shutdownRequested = false;

    constructor(logger?: Logger, metrics?: Metrics) {
        this.validator = new DomainValidator();
        this.logger = logger || new NoopLogger();
        this.metrics = metrics || new NoopMetrics();
        this.fetcher = new FetchManager(this.logger, this.metrics);
        this.dedupEngine = new DeduplicationEngine();
    }

    async build(sources: SourceConfig[], outputDir: string = './output'): Promise<BuildResult> {
        const startTime = Date.now();
        const timestamp = new Date().toISOString();
        
        const shutdownTimeout = setTimeout(() => {
            this.shutdownRequested = true;
            this.logger.warn('Shutdown requested, finishing current batch...');
        }, GRACEFUL_SHUTDOWN_TIMEOUT_MS);
        
        try {
            const validationContext: ValidationContext = {
                maxLabels: 127,
                blockPunycode: true,
                maxRiskScore: 50,
            };
            
            const enabledSources = sources.filter(s => s.enabled);
            this.logger.info(`Fetching ${enabledSources.length} sources...`);
            
            const fetchResults = await this.fetchAllSources(enabledSources);
            
            if (this.shutdownRequested) {
                throw new Error('Shutdown requested during fetch');
            }
            
            this.logger.info('Processing domains...');
            const processResult = await this.processDomains(fetchResults, validationContext);
            
            if (this.shutdownRequested) {
                throw new Error('Shutdown requested during processing');
            }
            
            this.logger.info('Generating output...');
            const outputPath = await this.generateOutput(processResult.domains, outputDir);
            
            const duration = Date.now() - startTime;
            this.logger.info('Build completed', { duration, domainCount: processResult.domains.length });
            
            this.metrics.recordGauge('blocklist.domains', processResult.domains.length);
            this.metrics.recordDuration('build.duration', duration);
            
            return {
                success: true,
                duration,
                domainCount: processResult.domains.length,
                outputPath,
                timestamp,
            };
        } catch (error) {
            this.logger.error('Build failed', error as Error);
            this.metrics.recordCounter('build.errors', 1);
            
            return {
                success: false,
                error: (error as Error).message,
                timestamp,
            };
        } finally {
            clearTimeout(shutdownTimeout);
        }
    }

    private async fetchAllSources(sources: SourceConfig[]): Promise<FetchResult[]> {
        const results: FetchResult[] = [];
        
        for (const source of sources) {
            if (this.shutdownRequested) break;
            
            try {
                const result = await this.fetcher.fetch(source.url, source.name, source.timeout);
                results.push(result);
                this.logger.debug(`Fetched ${source.name}`, {
                    bytes: result.data.length,
                    timeMs: result.fetchTimeMs,
                    cached: result.cached
                });
            } catch (error) {
                this.logger.warn(`Skipping ${source.name}`, { error: (error as Error).message });
                this.metrics.recordCounter('source.failed', 1, { source: source.name });
            }
        }
        
        if (results.length === 0) {
            throw new Error('No sources could be fetched');
        }
        
        return results;
    }

    private async processDomains(
        fetchResults: FetchResult[],
        validationContext: ValidationContext
    ): Promise<ProcessResult> {
        const allDomains: string[] = [];
        
        for (const result of fetchResults) {
            const domains = DomainParser.parse(result.data);
            allDomains.push(...domains);
            
            for (const domain of domains) {
                const validation = this.validator.validate(domain, validationContext);
                if (validation.isValid && validation.normalized) {
                    await this.dedupEngine.add(validation.normalized, result.sourceName);
                }
            }
        }
        
        const domains = this.dedupEngine.getAll();
        const stats = this.dedupEngine.getStats();
        
        return { domains, stats };
    }

    private async generateOutput(domains: string[], outputDir: string): Promise<string> {
        const format = domains.length > 500000 ? 'domains' : 'hosts';
        const content = OutputGenerator.generate(domains, format);
        return OutputGenerator.write(content, outputDir, format);
    }
}

// ============================================================================
// MAIN ENTRY POINT WITH GRACEFUL SHUTDOWN
// ============================================================================

const DEFAULT_SOURCES: SourceConfig[] = [
    { name: 'OISD Big', url: 'https://big.oisd.nl/domains', enabled: true, timeout: 30000 },
    { name: 'AdAway', url: 'https://adaway.org/hosts.txt', enabled: true, timeout: 30000 },
    { name: 'StevenBlack', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', enabled: true, timeout: 30000 },
    { name: 'Peter Lowe', url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0', enabled: true, timeout: 30000 },
];

async function main(): Promise<void> {
    const logger = pino({ 
        name: 'blocklist-builder', 
        level: process.env.LOG_LEVEL || 'info',
        formatters: { level: (label) => ({ level: label }) }
    });
    
    const metrics: Metrics = {
        recordDuration: (name, durationMs, labels) => logger.debug(`metric.${name}`, { durationMs, labels }),
        recordCounter: (name, value, labels) => logger.debug(`metric.${name}`, { value, labels }),
        recordGauge: (name, value, labels) => logger.debug(`metric.${name}`, { value, labels }),
    };
    
    const builder = new BlocklistBuilder(logger, metrics);
    
    let shuttingDown = false;
    const shutdownHandler = async (signal: string) => {
        if (shuttingDown) return;
        shuttingDown = true;
        
        logger.warn(`Received ${signal}, shutting down gracefully...`);
        
        const timeout = setTimeout(() => {
            logger.error('Graceful shutdown timeout, forcing exit');
            process.exit(1);
        }, GRACEFUL_SHUTDOWN_TIMEOUT_MS);
        
        try {
            await new Promise(resolve => setTimeout(resolve, 1000));
            process.exit(0);
        } finally {
            clearTimeout(timeout);
        }
    };
    
    process.on('SIGTERM', () => shutdownHandler('SIGTERM'));
    process.on('SIGINT', () => shutdownHandler('SIGINT'));
    
    try {
        const result = await builder.build(DEFAULT_SOURCES);
        
        if (result.success) {
            logger.info({ duration: result.duration, domainCount: result.domainCount }, 'Build successful');
            process.exit(0);
        } else {
            logger.error({ error: result.error }, 'Build failed');
            process.exit(1);
        }
    } catch (error) {
        logger.error({ error: (error as Error).message }, 'Fatal error');
        process.exit(1);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}

export { BlocklistBuilder, DomainValidator, DeduplicationEngine, OutputGenerator };
