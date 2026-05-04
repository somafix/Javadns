# DNS Blocklist Builder 🚀

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)](https://www.typescriptlang.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/yourusername/dns-blocklist-builder/pulls)
[![Downloads](https://img.shields.io/npm/dt/dns-blocklist-builder)](https://www.npmjs.com/package/dns-blocklist-builder)
[![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/dns-blocklist-builder/test.yml)](https://github.com/yourusername/dns-blocklist-builder/actions)

A production-ready DNS blocklist builder that aggregates, validates, deduplicates, and compresses blocklists from multiple sources. Perfect for ad-blocking, malware protection, and privacy enforcement.

## ✨ Features

- 🔄 **Parallel Downloads** - Fetch from multiple sources simultaneously (3-4x faster)
- 💾 **Smart Caching** - 24-hour TTL cache with auto-cleanup
- 🔁 **Auto Retry** - 3 attempts with exponential backoff
- ✅ **RFC-Compliant Validation** - Full domain validation (RFC 1035)
- 📊 **Detailed Statistics** - Track unique, duplicates, and invalid domains
- 🗜️ **Gzip Compression** - Level 9 compression for minimal storage
- 🎯 **Auto Format Selection** - Hosts format for <500k, domains format for >500k
- 🛡️ **Error Resilient** - Continues even if some sources fail
- 🚀 **Production Ready** - Tested and stable

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output](#output)
- [Performance](#performance)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## 🔧 Installation

### Global Installation
```bash
npm install -g dns-blocklist-builder
