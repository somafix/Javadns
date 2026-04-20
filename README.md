# DNS Blocklist Builder

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-prettier-ff69b4.svg)](https://prettier.io/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

A production-ready, high-performance DNS blocklist builder with advanced features including circuit breakers, retry logic, SSRF protection, caching, and graceful shutdown.

## 🚀 Features

- **Multi-Source Aggregation** - Combine multiple blocklist sources
- **Intelligent Deduplication** - Bloom filter + LRU cache for memory-efficient dedup
- **Automatic Caching** - Reduce network usage with smart caching (24h TTL)
- **Circuit Breaker Pattern** - Prevents cascading failures
- **SSRF Protection** - Blocks requests to private IP ranges
- **Graceful Shutdown** - Proper cleanup on SIGTERM/SIGINT
- **Domain Validation** - RFC-compliant domain validation with risk scoring
- **Multiple Output Formats** - Hosts file format or plain domains list
- **Compression Support** - Automatic GZip compression for outputs
- **Comprehensive Logging** - Structured logging with Pino
- **Metrics Collection** - Built-in performance metrics


## 📦 Installation

```bash
# Using npm
npm install dns-blocklist-builder

# Using yarn
yarn add dns-blocklist-builder

# Using pnpm
pnpm add dns-blocklist-builder

# Global installation (for CLI usage)
npm install -g dns-blocklist-builder
