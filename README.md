# 🚀 DNS Blocklist Builder

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2014.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build: Tool](https://img.shields.io/badge/Build-DNS%20Filter-blueviolet)](https://github.com/)

A lightweight, high-performance Node.js utility that aggregates, validates, and compresses DNS blocklists from multiple reputable sources.

## ✨ Features

* **Multi-Source Aggregation**: Automatically fetches domain lists from OISD, AdAway, StevenBlack, and Yoyo.
* **Smart Validation**: Rigorous domain validation (RFC compliant) ensuring no malformed entries enter your list.
* **Duplicate Removal**: Efficiently deduplicates millions of entries to keep your DNS server lean.
* **Fail-Safe Downloader**: Built-in retry logic (3 attempts) and caching to handle network instability.
* **Dual Output**: Generates both plain text and high-compression Gzip (`.gz`) files.
* **Adaptive Formatting**: Automatically switches between standard list format and `0.0.0.0` hosts format based on entry count.

## 🛠️ Installation

1. Clone this repository or copy the script.
2. Install dependencies:
   ```bash
   npm install axios
