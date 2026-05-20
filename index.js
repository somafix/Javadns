#!/usr/bin/env node

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { gzipSync } from 'zlib';
import axios, { AxiosError } from 'axios';

const CONFIG = {
    MAX_DOMAIN_LEN: 253,
    MAX_LABEL_LEN: 63,
    MAX_LABELS: 127,
    CACHE_TTL_MS: 86400000, // 24 hours
    REQUEST_TIMEOUT_MS: 30000,
    MAX_RETRIES: 3,
    RETRY_DELAY_MS: 1000,
    HOSTS_FORMAT_THRESHOLD: 500000,
    OUTPUT_DIR: './output',
    OUTPUT_FILE: 'blocklist.txt',
    GZIP_FILE: 'blocklist.txt.gz'
} as const;

const SOURCES = [
    'https://big.oisd.nl/domains',
    'https://adaway.org/hosts.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0'
] as const;

const LOOPBACK_IPS = new Set(['0.0.0.0', '127.0.0.1', '::1', '0']);

interface CacheEntry {
    data: string;
    timestamp: number;
}

class Downloader {
    private cache = new Map<string, CacheEntry>();

    private isExpired(timestamp: number): boolean {
        return Date.now() - timestamp > CONFIG.CACHE_TTL_MS;
    }

    private cleanCache(): void {
        for (const [url, { timestamp }] of this.cache) {
            if (this.isExpired(timestamp)) {
                this.cache.delete(url);
            }
        }
    }

    private async delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async get(url: string): Promise<string> {
        this.cleanCache();

        const cached = this.cache.get(url);
        if (cached) return cached.data;

        let lastError: Error | undefined;

        for (let attempt = 1; attempt <= CONFIG.MAX_RETRIES; attempt++) {
            try {
                const response = await axios.get<string>(url, { 
                    timeout: CONFIG.REQUEST_TIMEOUT_MS 
                });
                
                if (typeof response.data === 'string') {
                    this.cache.set(url, { 
                        data: response.data, 
                        timestamp: Date.now() 
                    });
                    return response.data;
                }
                
                throw new Error('Response is not a string');
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                
                if (attempt === CONFIG.MAX_RETRIES) {
                    throw new Error(`Failed to download ${url}: ${lastError.message}`);
                }
                
                await this.delay(CONFIG.RETRY_DELAY_MS * attempt);
            }
        }

        throw lastError || new Error(`Failed to download ${url}`);
    }
}

function validateDomain(domain: string): string | null {
    let normalized = domain.toLowerCase().trim();
    
    if (normalized.endsWith('.')) {
        normalized = normalized.slice(0, -1);
    }
    
    if (normalized.length < 3 || normalized.length > CONFIG.MAX_DOMAIN_LEN) {
        return null;
    }
    
    const labels = normalized.split('.');
    if (labels.length > CONFIG.MAX_LABELS) {
        return null;
    }
    
    for (const label of labels) {
        if (label.length === 0 || label.length > CONFIG.MAX_LABEL_LEN) {
            return null;
        }
        
        if (label[0] === '-' || label[label.length - 1] === '-') {
            return null;
        }
        
        if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(label)) {
            return null;
        }
    }
    
    return normalized;
}

function parseHostsLine(line: string): string | null {
    const trimmed = line.trim();
    
    if (!trimmed || trimmed[0] === '#' || trimmed[0] === '!') {
        return null;
    }
    
    const parts = trimmed.split(/\s+/);
    
    // Hosts format: IP domain
    if (parts.length >= 2 && LOOPBACK_IPS.has(parts[0])) {
        return parts[1].toLowerCase();
    }
    
    // Plain domain format
    if (parts.length === 1 && trimmed.length <= CONFIG.MAX_DOMAIN_LEN) {
        return trimmed.toLowerCase();
    }
    
    return null;
}

async function downloadSource(
    url: string, 
    index: number, 
    total: number,
    downloader: Downloader
): Promise<string[]> {
    const sourceName = new URL(url).hostname;
    process.stdout.write(`[${index}/${total}] ${sourceName}... `);
    
    try {
        const content = await downloader.get(url);
        const domains = content
            .split(/\r?\n/)
            .map(line => parseHostsLine(line))
            .filter((domain): domain is string => domain !== null);
        
        console.log(`${domains.length.toLocaleString()} domains`);
        return domains;
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.log(`Failed: ${message}`);
        return [];
    }
}

interface Statistics {
    totalDownloaded: number;
    validUnique: number;
    duplicateCount: number;
    invalidCount: number;
    duplicateRate: string;
}

function processDomains(allDomains: string[]): Statistics {
    const unique = new Set<string>();
    let invalidCount = 0;
    
    for (const domain of allDomains) {
        const valid = validateDomain(domain);
        if (valid) {
            unique.add(valid);
        } else {
            invalidCount++;
        }
    }
    
    const validUnique = unique.size;
    const duplicateCount = allDomains.length - validUnique - invalidCount;
    const duplicateRate = ((duplicateCount / allDomains.length) * 100).toFixed(1);
    
    return {
        totalDownloaded: allDomains.length,
        validUnique,
        duplicateCount,
        invalidCount,
        duplicateRate
    };
}

function generateOutput(domains: string[]): string {
    const useHostsFormat = domains.length < CONFIG.HOSTS_FORMAT_THRESHOLD;
    
    let output = [
        '# DNS Blocklist',
        `# Generated: ${new Date().toISOString()}`,
        `# Total domains: ${domains.length.toLocaleString()}`,
        `# Sources: ${SOURCES.length}`,
        '',
        ''
    ].join('\n');
    
    if (useHostsFormat) {
        const entries = domains.map(domain => `0.0.0.0 ${domain}\n:: ${domain}`);
        output += entries.join('\n');
    } else {
        output += domains.join('\n');
    }
    
    return output;
}

function saveOutput(output: string): { outputPath: string; gzipPath: string } {
    mkdirSync(CONFIG.OUTPUT_DIR, { recursive: true });
    
    const outputPath = join(CONFIG.OUTPUT_DIR, CONFIG.OUTPUT_FILE);
    const gzipPath = join(CONFIG.OUTPUT_DIR, CONFIG.GZIP_FILE);
    
    writeFileSync(outputPath, output);
    
    const compressed = gzipSync(output, { level: 9 });
    writeFileSync(gzipPath, compressed);
    
    return { outputPath, gzipPath };
}

async function main(): Promise<void> {
    console.log('\n🚀 DNS Blocklist Builder\n');
    
    const startTime = Date.now();
    const downloader = new Downloader();
    
    const downloadTasks = SOURCES.map((url, index) => 
        downloadSource(url, index + 1, SOURCES.length, downloader)
    );
    
    const results = await Promise.all(downloadTasks);
    const allDomains = results.flat();
    
    console.log(`\n📥 Total downloaded: ${allDomains.length.toLocaleString()}`);
    
    if (allDomains.length === 0) {
        throw new Error('No domains were downloaded from any source');
    }
    
    console.log(`\n🔍 Processing...`);
    const stats = processDomains(allDomains);
    
    console.log(`\n📊 Statistics:`);
    console.log(`   Valid unique:   ${stats.validUnique.toLocaleString()}`);
    console.log(`   Duplicates:     ${stats.duplicateCount.toLocaleString()}`);
    console.log(`   Invalid:        ${stats.invalidCount.toLocaleString()}`);
    console.log(`   Efficiency:     ${stats.duplicateRate}% duplicates removed`);
    
    if (stats.validUnique === 0) {
        throw new Error('No valid domains found after processing');
    }
    
    console.log(`\n💾 Generating output...`);
    const domains = [...new Set(allDomains.filter(validateDomain).map(d => d!))].sort();
    const output = generateOutput(domains);
    const { outputPath, gzipPath } = saveOutput(output);
    
    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    const sizeKB = (output.length / 1024).toFixed(0);
    const gzipSizeKB = (gzipSync(output).length / 1024).toFixed(0);
    
    console.log(`\n✅ Complete in ${duration}s`);
    console.log(`\n📁 Output files:`);
    console.log(`   ${outputPath} (${sizeKB} KB)`);
    console.log(`   ${gzipPath} (${gzipSizeKB} KB)`);
    console.log(`\n🌐 Total domains: ${domains.length.toLocaleString()}`);
}

main().catch(error => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`\n❌ Fatal error: ${message}`);
    process.exit(1);
});