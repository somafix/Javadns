# DNS Blocklist Builder 🚀

[![GitHub Actions](https://img.shields.io/github/actions/workflow/status/somafix/Javadns/autonomous.yml?branch=main&label=Build&logo=github)](https://github.com/somafix/Javadns/actions)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen?logo=node.js)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-prettier-ff69b4.svg)](https://prettier.io/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Downloads](https://img.shields.io/npm/dt/dns-blocklist-builder.svg)](https://www.npmjs.com/package/dns-blocklist-builder)

> 🛡️ A powerful, production-ready DNS blocklist builder that aggregates, validates, and deduplicates domains from multiple sources. Perfect for Pi-hole, AdGuard Home, and other DNS filtering solutions.

## ✨ Features

- 🔄 **Multi-source aggregation** - Combines blocklists from OISD, AdAway, StevenBlack, Peter Lowe, and more
- 🗜️ **Smart deduplication** - Removes duplicate entries with detailed statistics
- ✅ **Domain validation** - RFC-compliant domain validation with punycode blocking
- 💾 **Local caching** - 24-hour cache to reduce bandwidth and speed up subsequent runs
- 🔁 **Automatic retries** - Exponential backoff for failed downloads
- 📦 **Dual output formats** - Generates both hosts format and plain domains list
- 🗜️ **Gzip compression** - Automatically creates compressed versions for efficient distribution
- 🤖 **CI/CD ready** - Built-in GitHub Actions workflow for automated daily builds
- 📊 **Detailed statistics** - Shows duplicate rates, domain counts, and processing time
- 

### Global Installation

```bash
npm install -g dns-blocklist-builder
