#!/usr/bin/env node

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { gzipSync } from 'zlib';
import axios from 'axios';

const MAX_DOMAIN_LEN = 253;
const SOURCES = [
    'https://big.oisd.nl/domains',
    'https://adaway.org/hosts.txt',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0'
];

class Downloader {
    private cache = new Map<string, { data: string; time: number }>();
    
    private isExpired(time: number): boolean {
        return Date.now() - time > 86400000;
    }
    
    private cleanCache(): void {
        for (const [url, { time }] of this.cache) {
            if (this.isExpired(time)) this.cache.delete(url);
        }
    }
    
    async get(url: string): Promise<string> {
        this.cleanCache();
        
        const cached = this.cache.get(url);
        if (cached) return cached.data;
        
        for (let attempt = 1; attempt <= 3; attempt++) {
            try {
                const res = await axios.get(url, { timeout: 30000 });
                if (typeof res.data === 'string') {
                    this.cache.set(url, { data: res.data, time: Date.now() });
                    return res.data;
                }
            } catch {
                if (attempt === 3) throw new Error(`Failed to download ${url}`);
                await new Promise(r => setTimeout(r, 1000 * attempt));
            }
        }
        throw new Error(`Failed to download ${url}`);
    }
}

function validateDomain(domain: string): string | null {
    let d = domain.toLowerCase().trim();
    if (d.endsWith('.')) d = d.slice(0, -1);
    if (d.length < 3 || d.length > MAX_DOMAIN_LEN) return null;
    
    const parts = d.split('.');
    if (parts.length > 127) return null;
    
    for (const part of parts) {
        if (part.length === 0 || part.length > 63) return null;
        if (part[0] === '-' || part[part.length - 1] === '-') return null;
        if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(part)) return null;
    }
    return d;
}

function parseHostsLine(line: string): string | null {
    const trimmed = line.trim();
    if (!trimmed || trimmed[0] === '#' || trimmed[0] === '!') return null;
    
    const parts = trimmed.split(/\s+/);
    const ips = new Set(['0.0.0.0', '127.0.0.1', '::1', '0']);
    
    if (parts.length >= 2 && ips.has(parts[0])) {
        return parts[1].toLowerCase();
    }
    
    if (parts.length === 1 && trimmed.length <= MAX_DOMAIN_LEN) {
        return trimmed.toLowerCase();
    }
    
    return null;
}

async function downloadSource(url: string, index: number, total: number): Promise<string[]> {
    const downloader = new Downloader();
    try {
        process.stdout.write(`[${index}/${total}] ${url.split('/')[2]}... `);
        const content = await downloader.get(url);
        const domains = content.split(/\r?\n/)
            .map(line => parseHostsLine(line))
            .filter((d): d is string => d !== null);
        console.log(`${domains.length.toLocaleString()} domains`);
        return domains;
    } catch (error) {
        console.log(`Failed`);
        return [];
    }
}

async function main(): Promise<void> {
    console.log('\n🚀 DNS Blocklist Builder\n');
    
    const startTime = Date.now();
    const downloads = SOURCES.map((url, i) => downloadSource(url, i + 1, SOURCES.length));
    const allDomains = (await Promise.all(downloads)).flat();
    
    console.log(`\n📥 Total downloaded: ${allDomains.length.toLocaleString()}`);
    
    console.log(`\n🔍 Processing...`);
    const unique = new Set<string>();
    let invalid = 0;
    
    for (const domain of allDomains) {
        const valid = validateDomain(domain);
        if (valid) {
            unique.add(valid);
        } else {
            invalid++;
        }
    }
    
    const domains = [...unique].sort();
    const duplicateRate = ((allDomains.length - domains.length) / allDomains.length * 100).toFixed(1);
    
    console.log(`\n📊 Statistics:`);
    console.log(`   Valid unique:   ${domains.length.toLocaleString()}`);
    console.log(`   Duplicates:     ${(allDomains.length - domains.length - invalid).toLocaleString()}`);
    console.log(`   Invalid:        ${invalid.toLocaleString()}`);
    console.log(`   Efficiency:     ${duplicateRate}% duplicates removed`);
    
    if (domains.length === 0) {
        console.error(`\n❌ Error: No valid domains found`);
        process.exit(1);
    }
    
    console.log(`\n💾 Generating output...`);
    
    const useHostsFormat = domains.length < 500000;
    let output = `# DNS Blocklist\n# Generated: ${new Date().toISOString()}\n# Total domains: ${domains.length.toLocaleString()}\n# Sources: ${SOURCES.length}\n\n`;
    
    if (useHostsFormat) {
        for (const domain of domains) {
            output += `0.0.0.0 ${domain}\n:: ${domain}\n`;
        }
    } else {
        output += domains.join('\n');
    }
    
    mkdirSync('./output', { recursive: true });
    const outputPath = join('./output', `blocklist.txt`);
    const gzipPath = join('./output', `blocklist.txt.gz`);
    
    writeFileSync(outputPath, output);
    writeFileSync(gzipPath, gzipSync(output, { level: 9 }));
    
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
    console.error(`\n❌ Fatal error: ${error.message}`);
    process.exit(1);
});
