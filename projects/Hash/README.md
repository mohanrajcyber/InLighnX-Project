# Ultimate Hash Cracker

A Python-based **multi-hash cracking tool** that supports dictionary attacks, brute-force attacks, and basic hash detection.  
It supports a wide range of hash types and produces colorful terminal output with tables.

## Features
- Detects hash type automatically.
- Supports dictionary attack with threading.
- Brute-force attack with custom charset and max length.
- Colorful output using `colorama`.
- Nice formatted tables using `tabulate`.
- Supports hash types: MD2, MD4, MD5, SHA1, SHA2, SHA3, NTLM, RIPEMD, CRC16/32, Adler32.

## Installation

```bash
# Clone the repo
git clone <your-repo-url>
cd Hash

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

Usage
python3 hashcracker.py
