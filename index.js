#!/usr/bin/env node

import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import { gzipSync } from 'zlib';
import crypto from 'crypto';
import axios, { AxiosError } from 'axios';

// ============================================================================
// CONSTANTS
// ============================================================================

const MIN_DOMAIN_LENGTH = 3;
const MAX_DOMAIN_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
const MAX_RESPONSE_SIZE_BYTES = 100 * 1024 * 1024;
const DEFAULT_RETRY_ATTEMPTS = 3;
const RETRY_DELAY_MS = 1000;
const CACHE_TTL_MS = 86400000; // 24 часа

// ============================================================================
// RETRY LOGIC
// ============================================================================

async function withRetry<T>(
    fn: () => Promise<T>,
    maxAttempts: number = DEFAULT_RETRY_ATTEMPTS
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
            
            console.warn(`Retry attempt ${attempt}/${maxAttempts}: ${lastError.message}`);
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS * attempt));
        }
    }
    
    throw lastError;
}

// ============================================================================
// CACHE MANAGER
// ============================================================================

class CacheManager {
    private cacheDir: string;
    
    constructor(cacheDir: string = './cache') {
        this.cacheDir = cacheDir;
        mkdirSync(cacheDir, { recursive: true });
    }
    
    private getCachePath(url: string): string {
        const hash = crypto.createHash('sha256').update(url).digest('hex');
        return join(this.cacheDir, `${hash}.cache`);
    }
    
    get(url: string): string | null {
        try {
            const cachePath = this.getCachePath(url);
            if (!existsSync(cachePath)) return null;
            
            const stats = require('fs').statSync(cachePath);
            if (Date.now() - stats.mtimeMs > CACHE_TTL_MS) return null;
            
            return readFileSync(cachePath, 'utf8');
        } catch {
            return null;
        }
    }
    
    set(url: string, data: string): void {
        try {
            const cachePath = this.getCachePath(url);
            writeFileSync(cachePath, data, 'utf8');
        } catch (error) {
            console.warn(`Failed to write cache: ${(error as Error).message}`);
        }
    }
}

// ============================================================================
// FETCH MANAGER
// ============================================================================

class FetchManager {
    private cache: CacheManager;
    
    constructor() {
        this.cache = new CacheManager();
    }
    
    async fetch(url: string, sourceName: string): Promise<string> {
        // Проверяем кэш
        const cached = this.cache.get(url);
        if (cached) {
            console.log(`✓ Using cached ${sourceName}`);
            return cached;
        }
        
        // Скачиваем с ретраями
        const response = await withRetry(async () => {
            const res = await axios.get(url, {
                timeout: 30000,
                maxRedirects: 5,
                maxContentLength: MAX_RESPONSE_SIZE_BYTES,
                headers: {
                    'User-Agent': 'DNS-Blocklist-Builder/6.0',
                    'Accept-Encoding': 'gzip, deflate',
                },
                // Для Node.js 14-16: без AbortSignal.timeout
                // Используем просто timeout в axios
            });
            
            if (typeof res.data !== 'string') {
                throw new Error(`Invalid response type for ${sourceName}`);
            }
            
            return res.data;
        });
        
        // Сохраняем в кэш
        this.cache.set(url, response);
        console.log(`✓ Downloaded ${sourceName} (${(response.length / 1024 / 1024).toFixed(2)} MB)`);
        
        return response;
    }
}

// ============================================================================
// DOMAIN VALIDATOR
// ============================================================================

class DomainValidator {
    private static readonly DOMAIN_REGEX = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i;
    
    validate(domain: string): { isValid: boolean; normalized: string | null } {
        if (!domain || typeof domain !== 'string') {
            return { isValid: false, normalized: null };
        }
        
        let normalized = domain.normalize('NFKC').toLowerCase().trim();
        
        // Убираем точку в конце
        if (normalized.endsWith('.')) {
            normalized = normalized.slice(0, -1);
        }
        
        // Проверка длины
        if (normalized.length < MIN_DOMAIN_LENGTH || normalized.length > MAX_DOMAIN_LENGTH) {
            return { isValid: false, normalized: null };
        }
        
        // Блокируем punycode (опционально)
        if (normalized.startsWith('xn--')) {
            return { isValid: false, normalized: null };
        }
        
        // Проверяем каждый лейбл
        const labels = normalized.split('.');
        if (labels.length > 127) {
            return { isValid: false, normalized: null };
        }
        
        for (const label of labels) {
            if (label.length === 0 || label.length > MAX_LABEL_LENGTH) {
                return { isValid: false, normalized: null };
            }
            
            if (label.startsWith('-') || label.endsWith('-')) {
                return { isValid: false, normalized: null };
            }
            
            if (!DomainValidator.DOMAIN_REGEX.test(label)) {
                return { isValid: false, normalized: null };
            }
        }
        
        return { isValid: true, normalized };
    }
}

// ============================================================================
// DEDUPLICATION ENGINE
// ============================================================================

class DeduplicationEngine {
    private domains: Map<string, number> = new Map();
    private totalProcessed = 0;
    
    add(domain: string): boolean {
        this.totalProcessed++;
        
        if (this.domains.has(domain)) {
            this.domains.set(domain, (this.domains.get(domain) || 0) + 1);
            return false;
        }
        
        this.domains.set(domain, 1);
        return true;
    }
    
    getAll(): string[] {
        return Array.from(this.domains.keys()).sort();
    }
    
    getStats(): { unique: number; total: number; duplicateRate: number } {
        return {
            unique: this.domains.size,
            total: this.totalProcessed,
            duplicateRate: this.totalProcessed > 0 
                ? ((this.totalProcessed - this.domains.size) / this.totalProcessed) * 100 
                : 0,
        };
    }
}

// ============================================================================
// DOMAIN PARSER
// ============================================================================

class DomainParser {
    private static readonly HOSTS_IPS = new Set(['0.0.0.0', '127.0.0.1', '::1', '0']);
    
    static parse(content: string): string[] {
        const domains: string[] = [];
        const lines = content.split(/\r?\n/);
        
        for (const line of lines) {
            const trimmed = line.trim();
            
            // Пропускаем комментарии и пустые строки
            if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) {
                continue;
            }
            
            // hosts формат: IP domain
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2 && DomainParser.HOSTS_IPS.has(parts[0])) {
                const domain = parts[1].toLowerCase();
                if (this.isValidDomainFormat(domain)) {
                    domains.push(domain);
                }
            } 
            // domains формат: просто домен
            else if (this.isValidDomainFormat(trimmed)) {
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
// OUTPUT GENERATOR
// ============================================================================

class OutputGenerator {
    static generate(domains: string[], format: 'hosts' | 'domains'): string {
        const header = this.generateHeader(domains.length);
        let content = header;
        
        if (format === 'hosts') {
            for (const domain of domains) {
                content += `0.0.0.0 ${domain}\n`;
                content += `:: ${domain}\n`;
            }
        } else {
            content += domains.join('\n');
        }
        
        return content;
    }
    
    private static generateHeader(domainCount: number): string {
        const now = new Date().toISOString();
        return `# DNS Blocklist v6.0
# Generated: ${now}
# Total Domains: ${domainCount.toLocaleString()}
# ============================================================================

`;
    }
    
    static write(content: string, outputDir: string, format: string): string {
        const outputPath = resolve(outputDir, `blocklist.${format === 'hosts' ? 'txt' : 'domains'}`);
        mkdirSync(outputDir, { recursive: true });
        
        // Пишем обычный файл
        writeFileSync(outputPath, content, 'utf8');
        console.log(`✓ Written to ${outputPath}`);
        
        // Пишем сжатый файл
        const gzipPath = `${outputPath}.gz`;
        writeFileSync(gzipPath, gzipSync(content, { level: 9 }));
        console.log(`✓ Written compressed to ${gzipPath}`);
        
        return outputPath;
    }
}

// ============================================================================
// MAIN BUILDER
// ============================================================================

interface SourceConfig {
    name: string;
    url: string;
    enabled: boolean;
}

class BlocklistBuilder {
    private validator: DomainValidator;
    private fetcher: FetchManager;
    private dedupEngine: DeduplicationEngine;
    
    constructor() {
        this.validator = new DomainValidator();
        this.fetcher = new FetchManager();
        this.dedupEngine = new DeduplicationEngine();
    }
    
    async build(sources: SourceConfig[], outputDir: string = './output'): Promise<{
        success: boolean;
        domainCount?: number;
        outputPath?: string;
        error?: string;
    }> {
        const startTime = Date.now();
        
        try {
            // Фильтруем включенные источники
            const enabledSources = sources.filter(s => s.enabled);
            console.log(`\n📡 Fetching ${enabledSources.length} sources...\n`);
            
            // Скачиваем все источники
            const allDomains: string[] = [];
            for (const source of enabledSources) {
                try {
                    const content = await this.fetcher.fetch(source.url, source.name);
                    const domains = DomainParser.parse(content);
                    allDomains.push(...domains);
                    console.log(`  → ${source.name}: ${domains.length.toLocaleString()} domains`);
                } catch (error) {
                    console.error(`  ✗ ${source.name}: ${(error as Error).message}`);
                }
            }
            
            console.log(`\n🔍 Processing ${allDomains.length.toLocaleString()} total domains...`);
            
            // Валидируем и дедуплицируем
            for (const domain of allDomains) {
                const { isValid, normalized } = this.validator.validate(domain);
                if (isValid && normalized) {
                    this.dedupEngine.add(normalized);
                }
            }
            
            const stats = this.dedupEngine.getStats();
            console.log(`\n📊 Deduplication stats:`);
            console.log(`  → Unique domains: ${stats.unique.toLocaleString()}`);
            console.log(`  → Duplicate rate: ${stats.duplicateRate.toFixed(2)}%`);
            
            // Генерируем вывод
            const domains = this.dedupEngine.getAll();
            const format = domains.length > 500000 ? 'domains' : 'hosts';
            const content = OutputGenerator.generate(domains, format);
            const outputPath = OutputGenerator.write(content, outputDir, format);
            
            const duration = ((Date.now() - startTime) / 1000).toFixed(2);
            console.log(`\n✅ Build completed in ${duration}s`);
            
            return {
                success: true,
                domainCount: domains.length,
                outputPath,
            };
        } catch (error) {
            console.error(`\n❌ Build failed: ${(error as Error).message}`);
            return {
                success: false,
                error: (error as Error).message,
            };
        }
    }
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

const DEFAULT_SOURCES: SourceConfig[] = [
    { name: 'OISD Big', url: 'https://big.oisd.nl/domains', enabled: true },
    { name: 'AdAway', url: 'https://adaway.org/hosts.txt', enabled: true },
    { name: 'StevenBlack', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', enabled: true },
    { name: 'Peter Lowe', url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0', enabled: true },
];

async function main(): Promise<void> {
    console.log('🚀 DNS Blocklist Builder v6.0\n');
    
    const builder = new BlocklistBuilder();
    const result = await builder.build(DEFAULT_SOURCES);
    
    if (result.success) {
        console.log(`\n📁 Output: ${result.outputPath}`);
        console.log(`🌐 Total domains: ${result.domainCount?.toLocaleString()}`);
        process.exit(0);
    } else {
        console.error(`\n💥 Error: ${result.error}`);
        process.exit(1);
    }
}

// Запускаем только если файл выполняется напрямую
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}

export { BlocklistBuilder, DomainValidator, DeduplicationEngine, OutputGenerator };