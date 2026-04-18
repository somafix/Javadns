#!/usr/bin/env node

import { writeFileSync, mkdirSync, existsSync, readFileSync, promises as fsPromises } from 'fs';
import { join, resolve } from 'path';
import { gzipSync, brotliCompressSync } from 'zlib';
import crypto from 'crypto';
import { Mutex } from 'async-mutex';
import pino from 'pino';
import axios, { AxiosInstance } from 'axios';
import { BloomFilter } from 'bloom-filters';
import { HyperLogLog } from 'hyperloglog';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface SourceConfig {
  name: string;
  url: string;
  enabled: boolean;
  timeout?: number;
  retries?: number;
}

interface ValidationContext {
  strictLevel: 'low' | 'medium' | 'high';
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
}

// ============================================================================
// DOMAIN VALIDATOR
// ============================================================================

class DomainValidator {
  private static readonly MAX_DOMAIN_LENGTH = 253;
  private static readonly MAX_LABEL_LENGTH = 63;
  private static readonly DOMAIN_REGEX = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i;
  
  private static readonly CONFUSABLE_MAP = new Map([
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

    if (normalized.length < 3 || normalized.length > DomainValidator.MAX_DOMAIN_LENGTH) {
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
      if (label.length === 0 || label.length > DomainValidator.MAX_LABEL_LENGTH) {
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
// FETCH MANAGER
// ============================================================================

class FetchManager {
  private axiosInstance: AxiosInstance;
  private logger: pino.Logger;

  constructor(timeout: number = 30000) {
    this.logger = pino({ name: 'fetch-manager', level: 'warn' });
    this.axiosInstance = axios.create({
      timeout,
      maxRedirects: 5,
      validateStatus: (status) => status === 200,
      headers: {
        'User-Agent': 'DNS-Blocklist-Builder/6.0',
        'Accept': 'text/plain, text/html',
        'Accept-Encoding': 'gzip, deflate',
      },
    });
  }

  async fetch(url: string, sourceName: string, timeout?: number): Promise<FetchResult> {
    const startTime = Date.now();
    
    try {
      const response = await this.axiosInstance.get(url, {
        timeout: timeout || 30000,
        signal: AbortSignal.timeout(timeout || 30000),
      });
      
      return {
        data: response.data,
        sourceName,
        fetchTimeMs: Date.now() - startTime,
      };
    } catch (error) {
      this.logger.error({ url, sourceName, error: error.message }, 'Fetch failed');
      throw new Error(`Failed to fetch ${sourceName}: ${error.message}`);
    }
  }
}

// ============================================================================
// DEDUPLICATION ENGINE
// ============================================================================

class DeduplicationEngine {
  private domains: Map<string, DomainMetadata> = new Map();
  private bloomFilter: BloomFilter;
  private mutex = new Mutex();

  constructor(expectedSize: number = 5000000) {
    this.bloomFilter = new BloomFilter(expectedSize, 0.01);
  }

  async add(domain: string, source: string): Promise<boolean> {
    const release = await this.mutex.acquire();
    
    try {
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

  getStats(totalProcessed: number): DedupStats {
    return {
      uniqueDomains: this.domains.size,
      totalProcessed,
      duplicateRate: totalProcessed > 0 ? (1 - this.domains.size / totalProcessed) * 100 : 0,
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
    return `# DNS Blocklist v${this.VERSION}
# Generated: ${now}
# Total Domains: ${domainCount.toLocaleString()}
#
# ============================================================================
# END OF HEADER
# ============================================================================

`;
  }

  static async write(content: string, outputDir: string, format: string): Promise<string> {
    const outputPath = resolve(outputDir, `blocklist.${format === 'hosts' ? 'txt' : 'domains'}`);
    mkdirSync(outputDir, { recursive: true });
    await fsPromises.writeFile(outputPath, content, 'utf8');
    
    const gzipPath = `${outputPath}.gz`;
    await fsPromises.writeFile(gzipPath, gzipSync(content, { level: 9 }));
    
    return outputPath;
  }
}

// ============================================================================
// PARSER UTILITIES
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
    return /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i.test(domain) && domain.length <= 253;
  }
}

// ============================================================================
// MAIN BUILDER
// ============================================================================

class BlocklistBuilder {
  private validator: DomainValidator;
  private fetcher: FetchManager;
  private dedupEngine: DeduplicationEngine;
  private logger: pino.Logger;

  constructor() {
    this.validator = new DomainValidator();
    this.fetcher = new FetchManager();
    this.dedupEngine = new DeduplicationEngine();
    this.logger = pino({ name: 'blocklist-builder', level: 'info' });
  }

  async build(sources: SourceConfig[], outputDir: string = './output'): Promise<BuildResult> {
    const startTime = Date.now();
    const timestamp = new Date().toISOString();
    
    try {
      this.printBanner();
      
      const validationContext: ValidationContext = {
        strictLevel: 'high',
        maxLabels: 127,
        blockPunycode: true,
        maxRiskScore: 50,
      };
      
      const enabledSources = sources.filter(s => s.enabled);
      this.logger.info(`Fetching ${enabledSources.length} sources...`);
      
      const fetchResults = await this.fetchAllSources(enabledSources);
      
      this.logger.info('Processing domains...');
      const processResult = await this.processDomains(fetchResults, validationContext);
      
      this.logger.info('Generating output...');
      const outputPath = await this.generateOutput(processResult.domains, outputDir);
      
      const duration = Date.now() - startTime;
      this.logger.info({ duration, domainCount: processResult.domains.length }, 'Build completed');
      
      return {
        success: true,
        duration,
        domainCount: processResult.domains.length,
        outputPath,
        timestamp,
      };
    } catch (error) {
      this.logger.error({ error: error.message }, 'Build failed');
      return {
        success: false,
        error: error.message,
        timestamp,
      };
    }
  }

  private async fetchAllSources(sources: SourceConfig[]): Promise<FetchResult[]> {
    const results: FetchResult[] = [];
    
    for (const source of sources) {
      try {
        const result = await this.fetcher.fetch(source.url, source.name, source.timeout);
        results.push(result);
        this.logger.debug(`Fetched ${source.name}: ${result.data.length} bytes in ${result.fetchTimeMs}ms`);
      } catch (error) {
        this.logger.warn(`Skipping ${source.name}: ${error.message}`);
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
    let totalProcessed = 0;
    
    for (const result of fetchResults) {
      const domains = DomainParser.parse(result.data);
      
      for (const domain of domains) {
        const validation = this.validator.validate(domain, validationContext);
        
        if (validation.isValid && validation.normalized) {
          const added = await this.dedupEngine.add(validation.normalized, result.sourceName);
          if (added) {
            totalProcessed++;
          }
        }
      }
    }
    
    const domains = this.dedupEngine.getAll();
    const stats = this.dedupEngine.getStats(totalProcessed);
    
    return { domains, stats };
  }

  private async generateOutput(domains: string[], outputDir: string): Promise<string> {
    const format = domains.length > 500000 ? 'domains' : 'hosts';
    const content = OutputGenerator.generate(domains, format);
    return OutputGenerator.write(content, outputDir, format);
  }

  private printBanner(): void {
    console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    DNS Blocklist Builder v6.0 - Production Ready              ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    `);
  }
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

const DEFAULT_SOURCES: SourceConfig[] = [
  { name: 'OISD Big', url: 'https://big.oisd.nl/domains', enabled: true, timeout: 30000 },
  { name: 'AdAway', url: 'https://adaway.org/hosts.txt', enabled: true, timeout: 30000 },
  { name: 'StevenBlack', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', enabled: true, timeout: 30000 },
  { name: 'Peter Lowe', url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0', enabled: true, timeout: 30000 },
];

async function main(): Promise<void> {
  try {
    const builder = new BlocklistBuilder();
    const result = await builder.build(DEFAULT_SOURCES);
    
    if (result.success) {
      console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           BUILD SUCCESSFUL                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Duration:      ${(result.duration! / 1000).toFixed(2)} seconds                                          ║
║  Domains:       ${result.domainCount!.toLocaleString()}                                                   ║
║  Output:        ${result.outputPath}                                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
      `);
      process.exit(0);
    } else {
      console.error(`\nBuild failed: ${result.error}`);
      process.exit(1);
    }
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { BlocklistBuilder, DomainValidator, DeduplicationEngine, OutputGenerator };
