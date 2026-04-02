#!/usr/bin/env node

import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { gzipSync } from 'zlib';

const CONFIG = {
  outputDir: './output',
  maxDomains: 2_000_000,
  sources: [
    { name: 'OISD Big', url: 'https://big.oisd.nl/domains', type: 'domains' },
    { name: 'AdAway', url: 'https://adaway.org/hosts.txt', type: 'hosts' },
    { name: 'StevenBlack', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', type: 'hosts' },
    { name: 'Disconnect.me', url: 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', type: 'domains' },
    { name: 'Peter Lowe', url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0', type: 'hosts' },
  ]
};

function parseLine(line, type) {
  const trimmed = line.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) return null;
  
  if (type === 'hosts') {
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2 && ['0.0.0.0', '127.0.0.1', '::1'].includes(parts[0])) {
      return parts[1].replace(/\.$/, '');
    }
  } else if (type === 'domains') {
    return trimmed.replace(/\.$/, '');
  }
  return null;
}

async function fetchSource(url, type) {
  console.log(`  📥 ${url.split('/')[2]}...`);
  try {
    const res = await fetch(url, { 
      headers: { 'User-Agent': 'DNS-Blocklist-Builder/3.0' },
      signal: AbortSignal.timeout(30000)
    });
    
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    
    const text = await res.text();
    const domains = new Set();
    
    for (const line of text.split('\n')) {
      const domain = parseLine(line, type);
      if (domain && domain.includes('.') && domain.length > 3 && domain.length < 253) {
        domains.add(domain);
      }
    }
    
    console.log(`     ✅ ${domains.size} domains`);
    return domains;
  } catch (err) {
    console.log(`     ❌ ${err.message}`);
    return new Set();
  }
}

async function main() {
  console.log(`
╔════════════════════════════════════════╗
║   DNS Blocklist Builder - Zero Deps   ║
║   No npm install required!            ║
╚════════════════════════════════════════╝
  `);
  
  console.log('📡 Fetching sources...\n');
  
  const allDomains = new Set();
  
  for (const source of CONFIG.sources) {
    const domains = await fetchSource(source.url, source.type);
    for (const d of domains) {
      if (allDomains.size < CONFIG.maxDomains) {
        allDomains.add(d);
      }
    }
  }
  
  const sorted = Array.from(allDomains).sort();
  console.log(`\n📊 Total unique domains: ${sorted.length.toLocaleString()}`);
  
  // Создаем output директорию
  mkdirSync(CONFIG.outputDir, { recursive: true });
  
  // Генерируем timestamp
  const timestamp = new Date().toISOString();
  const header = `# DNS Security Blocklist\n# Generated: ${timestamp}\n# Total: ${sorted.length}\n# Sources: ${CONFIG.sources.length}\n\n`;
  
  // Формат hosts (основной)
  let hosts = header;
  for (const domain of sorted) {
    hosts += `0.0.0.0 ${domain}\n`;
  }
  writeFileSync(join(CONFIG.outputDir, 'blocklist.txt'), hosts);
  console.log(`💾 Saved: ${CONFIG.outputDir}/blocklist.txt`);
  
  // Формат plain domains (для Pi-hole)
  let plain = header;
  for (const domain of sorted) {
    plain += `${domain}\n`;
  }
  writeFileSync(join(CONFIG.outputDir, 'domains.txt'), plain);
  
  // GZIP сжатая версия
  const compressed = gzipSync(hosts);
  writeFileSync(join(CONFIG.outputDir, 'blocklist.txt.gz'), compressed);
  console.log(`🗜️ Compressed: ${(compressed.length / 1024).toFixed(1)} KB`);
  
  // JSON метаданные
  writeFileSync(join(CONFIG.outputDir, 'metadata.json'), JSON.stringify({
    timestamp,
    total: sorted.length,
    sources: CONFIG.sources.map(s => s.name),
    size_bytes: hosts.length
  }, null, 2));
  
  console.log(`\n✅ Done! Total size: ${(hosts.length / 1024 / 1024).toFixed(2)} MB`);
}

main().catch(console.error);
