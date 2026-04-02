#!/usr/bin/env node

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import fetch from 'node-fetch';
import initSqlJs from 'sql.js';
import { Cron } from 'croner';
import { execSync } from 'child_process';

// ============ КОНФИГ ============
const CONFIG = {
  maxDomains: 2000000,
  maxAgeDays: 30,
  outputDir: './output',
  dataDir: './data',
  sources: [
    { name: 'OISD Big', url: 'https://big.oisd.nl/domains', type: 'domains', priority: 1 },
    { name: 'AdAway', url: 'https://adaway.org/hosts.txt', type: 'hosts', priority: 2 },
    { name: 'StevenBlack', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', type: 'hosts', priority: 3 },
    { name: 'Disconnect.me Tracking', url: 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', type: 'domains', priority: 4 },
    { name: 'Disconnect.me Ads', url: 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt', type: 'domains', priority: 4 },
    { name: 'Peter Lowe', url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0', type: 'hosts', priority: 5 },
    { name: 'MalwareDomains', url: 'https://mirror1.malwaredomains.com/files/justdomains', type: 'domains', priority: 5 },
    { name: 'Ransomware Tracker', url: 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt', type: 'domains', priority: 5 },
    { name: 'CoinBlocker', url: 'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt', type: 'domains', priority: 6 },
    { name: 'EasyList', url: 'https://easylist.to/easylist/easylist.txt', type: 'adblock', priority: 3 }
  ]
};

// ============ SQLite ИНИЦИАЛИЗАЦИЯ ============
let db;
let dbBuffer;

async function initDB() {
  mkdirSync(CONFIG.dataDir, { recursive: true });
  const SQL = await initSqlJs();
  
  if (existsSync(join(CONFIG.dataDir, 'blocklist.db'))) {
    const buffer = readFileSync(join(CONFIG.dataDir, 'blocklist.db'));
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }
  
  // Создаем таблицы если нет
  db.run(`
    CREATE TABLE IF NOT EXISTS domains (
      domain TEXT PRIMARY KEY,
      category TEXT,
      first_seen INTEGER,
      last_seen INTEGER,
      source TEXT,
      active INTEGER DEFAULT 1
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS sources (
      url TEXT PRIMARY KEY,
      last_fetch INTEGER,
      etag TEXT
    )
  `);
  
  return db;
}

function saveDB() {
  const data = db.export();
  const buffer = Buffer.from(data);
  writeFileSync(join(CONFIG.dataDir, 'blocklist.db'), buffer);
  console.log(`💾 Database saved: ${buffer.length} bytes`);
}

// ============ ПАРСИНГ ============
function parseLine(line, type) {
  const trimmed = line.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!') || trimmed.startsWith('[')) {
    return null;
  }
  
  let domain = null;
  
  if (type === 'hosts') {
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2 && ['0.0.0.0', '127.0.0.1', '::1'].includes(parts[0])) {
      domain = parts[1];
    }
  } else if (type === 'domains') {
    domain = trimmed;
  } else if (type === 'adblock') {
    const match = trimmed.match(/^\|\|([a-z0-9.-]+)\^/);
    if (match) domain = match[1];
  }
  
  if (domain && domain.includes('.') && domain.length < 253 && domain.length > 3) {
    return domain.replace(/\.$/, '');
  }
  return null;
}

// ============ ФЕТЧИНГ ИСТОЧНИКОВ ============
async function fetchSource(url, type) {
  console.log(`  📥 Fetching ${url}`);
  
  const now = Date.now();
  const domains = new Set();
  
  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'DNS-Blocklist-Builder/3.0' },
      timeout: 30000
    });
    
    if (!response.ok) {
      console.log(`  ⚠️ HTTP ${response.status}`);
      return domains;
    }
    
    const text = await response.text();
    const lines = text.split('\n');
    
    for (const line of lines) {
      const domain = parseLine(line, type);
      if (domain) domains.add(domain);
    }
    
    console.log(`  ✅ Got ${domains.size} domains`);
    
    // Обновляем источник в БД
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO sources (url, last_fetch) VALUES (?, ?)
    `);
    stmt.run([url, now]);
    
  } catch (err) {
    console.log(`  ❌ Failed: ${err.message}`);
  }
  
  return domains;
}

// ============ ОБНОВЛЕНИЕ ДОМЕНОВ В БД ============
async function updateDomains(newDomains, sourceUrl) {
  const now = Date.now();
  let added = 0;
  
  // Получаем текущие активные домены
  const currentStmt = db.prepare(`SELECT domain FROM domains WHERE active = 1`);
  const currentDomains = new Set(currentStmt.all().map(r => r.domain));
  
  // Добавляем новые
  for (const domain of newDomains) {
    const exists = db.prepare(`SELECT 1 FROM domains WHERE domain = ?`).get([domain]);
    
    if (!exists) {
      db.run(`
        INSERT INTO domains (domain, category, first_seen, last_seen, source, active)
        VALUES (?, ?, ?, ?, ?, 1)
      `, [domain, 'unknown', now, now, sourceUrl]);
      added++;
    } else {
      // Обновляем last_seen
      db.run(`UPDATE domains SET last_seen = ?, active = 1 WHERE domain = ?`, [now, domain]);
    }
  }
  
  // Помечаем старые как неактивные
  const staleDate = now - (CONFIG.maxAgeDays * 24 * 60 * 60 * 1000);
  const staleResult = db.run(`
    UPDATE domains SET active = 0 
    WHERE last_seen < ? AND active = 1
  `, [staleDate]);
  
  console.log(`  ➕ Added: ${added}, 🔄 Active: ${newDomains.size}, 🧹 Stale: ${staleResult.changes || 0}`);
  
  return { added, stale: staleResult.changes || 0 };
}

// ============ ГЕНЕРАЦИЯ ВЫХОДНЫХ ФАЙЛОВ ============
async function generateOutputs() {
  mkdirSync(CONFIG.outputDir, { recursive: true });
  
  // Получаем активные домены
  const domains = db.prepare(`
    SELECT domain FROM domains WHERE active = 1 ORDER BY domain
  `).all();
  
  console.log(`\n📊 Total active domains: ${domains.length}`);
  
  const timestamp = new Date().toISOString();
  const header = `# DNS Security Blocklist\n# Generated: ${timestamp}\n# Total: ${domains.length}\n\n`;
  
  // Формат hosts
  let hostsContent = header;
  for (const row of domains) {
    hostsContent += `0.0.0.0 ${row.domain}\n`;
  }
  writeFileSync(join(CONFIG.outputDir, 'blocklist.txt'), hostsContent);
  
  // Простой список доменов (для Pi-hole и AdGuard)
  let domainsContent = header;
  for (const row of domains) {
    domainsContent += `${row.domain}\n`;
  }
  writeFileSync(join(CONFIG.outputDir, 'domains.txt'), domainsContent);
  
  // Формат для dnsmasq
  let dnsmasqContent = `# Dnsmasq format\n`;
  for (const row of domains) {
    dnsmasqContent += `address=/${row.domain}/0.0.0.0\n`;
  }
  writeFileSync(join(CONFIG.outputDir, 'dnsmasq.conf'), dnsmasqContent);
  
  // JSON с метаданными
  writeFileSync(join(CONFIG.outputDir, 'metadata.json'), JSON.stringify({
    timestamp,
    total: domains.length,
    config: {
      maxDomains: CONFIG.maxDomains,
      maxAgeDays: CONFIG.maxAgeDays
    }
  }, null, 2));
  
  console.log(`💾 Generated 4 output files in ${CONFIG.outputDir}`);
  return domains.length;
}

// ============ ПУШ В GITHUB ============
function pushToGitHub() {
  try {
    console.log('\n📤 Pushing to GitHub...');
    execSync('git config user.name "DNS Daemon"', { stdio: 'inherit' });
    execSync('git config user.email "daemon@local"', { stdio: 'inherit' });
    execSync('git add output/ data/', { stdio: 'inherit' });
    
    // Проверяем есть ли изменения
    const status = execSync('git diff --staged --quiet', { stdio: 'pipe' });
    if (status.status === 0) {
      console.log('  No changes to commit');
      return false;
    }
    
    execSync(`git commit -m "🤖 Auto-update ${new Date().toISOString().slice(0,19)} [skip ci]"`, { stdio: 'inherit' });
    execSync('git push', { stdio: 'inherit' });
    console.log('  ✅ Pushed successfully');
    return true;
  } catch (err) {
    console.log(`  ⚠️ Push failed: ${err.message}`);
    return false;
  }
}

// ============ ОСНОВНОЙ ЦИКЛ ============
async function updateAll() {
  console.log(`\n${'='.repeat(50)}`);
  console.log(`🔄 UPDATE STARTED at ${new Date().toISOString()}`);
  console.log(`${'='.repeat(50)}`);
  
  let totalNewDomains = new Set();
  let stats = { added: 0, stale: 0 };
  
  for (const source of CONFIG.sources) {
    console.log(`\n📡 Source: ${source.name}`);
    const domains = await fetchSource(source.url, source.type);
    
    for (const domain of domains) {
      totalNewDomains.add(domain);
    }
  }
  
  console.log(`\n📊 Total unique domains from all sources: ${totalNewDomains.size}`);
  
  // Обновляем БД
  const result = await updateDomains(totalNewDomains, 'aggregated');
  
  // Генерируем файлы
  const total = await generateOutputs();
  
  // Сохраняем БД
  saveDB();
  
  // Пушим в GitHub
  pushToGitHub();
  
  console.log(`\n✅ UPDATE COMPLETE: ${total} domains active`);
  return total;
}

// ============ ЗАПУСК ============
async function main() {
  console.log(`
╔═══════════════════════════════════════╗
║   DNS Blocklist Autonomous Daemon     ║
║   Version 3.0 - JavaScript Edition    ║
╚═══════════════════════════════════════╝
  `);
  
  await initDB();
  
  // Запускаем сразу
  await updateAll();
  
  // Планируем следующие запуски (каждые 6 часов)
  if (process.argv.includes('--daemon')) {
    console.log('\n⏰ Scheduling next runs: 00, 06, 12, 18 UTC');
    new Cron('0 */6 * * *', async () => {
      await updateAll();
    });
  }
}

// Запускаем
main().catch(console.error);
