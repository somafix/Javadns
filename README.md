# DNS Blocklist Builder

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2018.0.0-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://github.com/prettier/prettier)

A highly efficient, zero-dependency (external system-wise) Node.js CLI tool written in TypeScript to aggregate, normalize, validate, and compress DNS blocklists from multiple upstream sources.

---

## 🚀 Features

*   **Multi-Source Aggregation:** Concurrently downloads blocklists from reputable providers (OISD, AdAway, StevenBlack, Yoyo).
*   **Smart Parsing:** Automatically handles both standard `hosts` file formats (e.g., `0.0.0.0 domain.com`) and plain domain lists.
*   **Strict RFC Validation:** Filters out malformed domains based on length, allowed characters, and structure rules.
*   **Resilient Downloader:** Built-in retry mechanism with exponential-like delay backoff, request timeouts, and an in-memory cache layer.
*   **Adaptive Output Format:** Automatically switches format based on the blocklist size:
    *   **Hosts format** (`0.0.0.0 domain`) if the total domain count is under 500,000.
    *   **Plain domain list** format if it exceeds the threshold for optimal performance.
*   **Automated Compression:** Generates both a raw `.txt` file and a maximum-compression `.txt.gz` file.

---

## ⚙️ Configuration

The script uses a strict internal `CONFIG` object to control limits and behaviors:

| Parameter | Default Value | Description |
| :--- | :--- | :--- |
| `MAX_DOMAIN_LEN` | `253` | Maximum total length of a valid domain name. |
| `MAX_LABEL_LEN` | `63` | Maximum length of a single domain label (e.g., `www`). |
| `CACHE_TTL_MS` | `86400000` | In-memory cache lifetime (24 hours). |
| `MAX_RETRIES` | `3` | Number of attempts to fetch a source before failing. |
| `RETRY_DELAY_MS`| `1000` | Base delay multiplier between retry attempts. |
| `HOSTS_FORMAT_THRESHOLD` | `500000` | Domain count threshold determining the output format. |
| `OUTPUT_DIR` | `'./output'` | Directory where the final lists will be saved. |

---

## 📦 Upstream Sources Included

By default, the builder pulls data from:
1. `big.oisd.nl`
2. `adaway.org`
3. `StevenBlack/hosts`
4. `pgl.yoyo.org`

---

## 🛠️ Installation & Usage

### Prerequisites
*   Node.js (v18.0.0 or higher recommended)
*   npm or yarn

### Setup
1. Clone your repository or save the script file.
2. Install the required dependencies:
```bash
npm install axios
npm install --save-dev typescript @types/node
