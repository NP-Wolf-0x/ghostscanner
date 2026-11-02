# GhostScanner Professional

**Fast Asynchronous Port Scanner with Nmap Integration**

> High-speed TCP/UDP discovery tool designed for authorized penetration testing and red team operations.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0.0-orange)

## Overview

GhostScanner is a modern asynchronous port scanner focused on **speed** and clean integration with professional tooling (especially Nmap).

It is designed for the discovery phase of authorized security assessments.

### Key Features

- High-speed asynchronous TCP scanning
- Basic UDP scanning
- Banner grabbing
- Stealth mode (randomized timing)
- Automatic Nmap hand-off (`--nmap`)
- Support for custom Nmap arguments (decoys, scripts, etc.)
- JSON / CSV / PDF reporting
- Clean terminal output

## Installation

```bash
git clone https://github.com/NP-Wolf-0x/ghostscanner.git
cd ghostscanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt