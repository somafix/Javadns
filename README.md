# DNS Blocklist Builder v6.0

[![TypeScript](https://img.shields.io/badge/Language-TypeScript-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Version-6.0.0-orange.svg)]()

A high-performance, production-ready utility designed to aggregate, sanitize, and deduplicate DNS blocklists from multiple sources. It handles large-scale domain processing using memory-efficient structures like Bloom Filters.

## Features

- **Multi-Source Fetching:** Aggregates lists from OISD, AdAway, StevenBlack, and more.
- **Advanced Validation:**
  - Strict format checking (Length, Labels, Syntax).
  - Punycode detection and filtering.
  - Confusable character detection (Homograph attack prevention).
- **High-Performance Deduplication:** Uses a `BloomFilter` to drastically reduce memory overhead when processing millions of domains.
- **Automatic Output:** Automatically decides between `hosts` format or plain `domains` format based on output size, with Gzip compression included.
- **Async Processing:** Utilizes `async-mutex` for thread-safe handling of domain metadata.

## Prerequisites

Ensure you have [Node.js](https://nodejs.org/) (v18+) installed.

You will need the following dependencies:
```bash
npm install axios pino async-mutex bloom-filters hyperloglog

