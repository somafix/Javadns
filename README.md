# 🚁 DroneGuard v6.0 — Industrial RF Detection System

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.100%2B-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/Security-Bandit%20Pass-brightgreen)
![Static Analysis](https://img.shields.io/badge/mypy-Strict-informational)

**DroneGuard** is a high-performance, asynchronous RF monitoring and drone detection system. It leverages Digital Signal Processing (DSP) and spectral analysis to identify drone signatures in real-time via SDR (Software Defined Radio) simulation.

---

## 🛠 Key Features

- **Asynchronous Engine**: Powered by `FastAPI` and `asyncio` for non-blocking concurrent scanning and API serving.
- **Advanced DSP**: Spectral analysis using **Blackman Windowing** and **Real FFT** for high-precision peak detection.
- **Thread-Safe Architecture**: SQLite integration with **WAL (Write-Ahead Logging)** mode and thread-local connection management.
- **Industrial Logic**: Automated threat level assessment (Low, Medium, High, Critical) based on SNR and frequency matching.
- **SDR-Ready**: Modular design allows seamless swapping of simulation data with real SDR drivers (RTL-SDR, HackRF, etc.).

---

## 🏗 System Architecture

1. **Scan Engine**: Simulates/Acquires IQ samples and processes them in a background task.
2. **Signal Analyzer**: Performs PSD (Power Spectral Density) calculation and noise floor estimation.
3. **Signature Detector**: Matches detected signals against a hardened database of known drone profiles.
4. **FastAPI Layer**: Provides a RESTful interface for historical data, system health, and signature management.

---

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.9+ installed.

```bash
pip install fastapi uvicorn numpy pydantic
