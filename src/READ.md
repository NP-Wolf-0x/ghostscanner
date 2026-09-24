# GhostScanner

**High-performance asynchronous port scanner**

> Hits thousands of ports per second with stealth timing, service detection, and clean report export.

## Features

- Asynchronous scanning (high speed)
- Stealth mode with randomized jitter
- Banner grabbing + service detection
- Clean colored table output
- Export to **JSON**, **CSV**, and **PDF**
- `--top` flag for most common ports
- Performance statistics (ports/sec)

## Installation

```bash
cd GhostScanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .