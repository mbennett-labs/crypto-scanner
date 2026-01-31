# Crypto Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A CLI tool for scanning directories for cryptographic usage and generating quantum-vulnerability risk assessments.**

Developed by [Quantum Shield Labs](https://quantumshieldlabs.dev)

---

## Overview

Crypto Scanner analyzes your codebase to identify cryptographic algorithms that may be vulnerable to quantum computing attacks. It scans source code, configuration files, and certificates to provide a comprehensive risk assessment with actionable recommendations.

### Key Features

- **Multi-language support**: Python, JavaScript/TypeScript, Java, Go, Rust, C/C++, and more
- **Certificate analysis**: Parse X.509 certificates to extract algorithm details
- **Configuration scanning**: Detect crypto settings in YAML, JSON, ENV, and config files
- **Risk classification**: Four-tier risk model (Critical, High, Medium, Low)
- **Multiple output formats**: JSON for automation, HTML for stakeholder reports
- **Quantum-focused**: Prioritizes identification of algorithms vulnerable to Shor's algorithm

---

## Installation

### From Source

```bash
git clone https://github.com/mbennett-labs/crypto-scanner.git
cd crypto-scanner
pip install -e .
```

### Dependencies

- Python 3.10+
- typer (CLI framework)
- rich (terminal formatting)
- pydantic (data validation)
- cryptography (certificate parsing)
- pyyaml (YAML parsing)

---

## Quick Start

```bash
# Scan current directory
crypto-scanner scan .

# Scan with verbose output
crypto-scanner scan /path/to/project --verbose

# Generate HTML report
crypto-scanner scan . --html --output report.html

# Exclude directories
crypto-scanner scan . --exclude node_modules --exclude vendor
```

---

## Usage

### Basic Scan

```bash
crypto-scanner scan <directory>
```

Scans the specified directory and outputs a JSON report to stdout.

### Command Options

| Option | Short | Description |
|--------|-------|-------------|
| `--html` | | Generate HTML report instead of JSON |
| `--output` | `-o` | Save report to file |
| `--verbose` | `-v` | Show detailed progress |
| `--exclude` | `-e` | Exclude patterns (can be repeated) |

### Examples

```bash
# Scan and save JSON report
crypto-scanner scan ./src --output crypto-report.json

# Generate HTML report with QSL branding
crypto-scanner scan . --html --output quantum-assessment.html

# Verbose scan with exclusions
crypto-scanner scan . -v --exclude "*.test.js" --exclude "__pycache__"

# Show supported file types and risk levels
crypto-scanner info
```

---

## Risk Classification

### Critical (Quantum-Vulnerable)

Algorithms vulnerable to Shor's algorithm on quantum computers:

| Algorithm | Status |
|-----------|--------|
| RSA | All key sizes vulnerable |
| ECDSA/ECC | All curves vulnerable |
| DH/ECDH | Key exchange vulnerable |
| DSA | Deprecated + vulnerable |

**Action**: Plan migration to post-quantum cryptography (ML-KEM, ML-DSA)

### High (Deprecated/Weak)

Algorithms with known weaknesses:

| Algorithm | Issue |
|-----------|-------|
| MD5 | Collision attacks, broken |
| SHA-1 | Collision attacks, deprecated |
| DES | 56-bit key, easily broken |
| 3DES | Deprecated, slow |
| AES-128 | Grover's algorithm concern |

**Action**: Update to current standards immediately

### Medium (Monitor)

Acceptable algorithms that should be monitored:

| Algorithm | Status |
|-----------|--------|
| SHA-256 | Secure, plan SHA-3 migration |
| SHA-384 | Secure |
| SHA-512 | Good quantum resistance |

**Action**: Continue monitoring, plan future upgrades

### Low (Adequate)

Quantum-resistant or adequate algorithms:

| Algorithm | Status |
|-----------|--------|
| AES-256 | Quantum-resistant |
| ChaCha20 | Modern, secure |
| SHA-3 | Latest standard |
| ML-KEM | Post-quantum (Kyber) |
| ML-DSA | Post-quantum (Dilithium) |

**Action**: No immediate action required

---

## Supported File Types

### Source Code
`.py`, `.js`, `.ts`, `.tsx`, `.java`, `.go`, `.rs`, `.c`, `.cpp`, `.cs`, `.rb`, `.php`, `.swift`, `.kt`

### Configuration
`.conf`, `.yaml`, `.yml`, `.json`, `.env`, `.ini`, `.toml`, `.cfg`

### Certificates
`.pem`, `.crt`, `.cer`, `.cert`, `.der`

---

## Output Formats

### JSON Report

Default output format, ideal for CI/CD pipelines and automation:

```json
{
  "scan_directory": "/path/to/project",
  "scan_timestamp": "2025-01-30T10:30:00",
  "scanner_version": "0.1.0",
  "summary": {
    "total_files_scanned": 150,
    "total_findings": 23,
    "critical_count": 5,
    "high_count": 8,
    "medium_count": 7,
    "low_count": 3
  },
  "findings": [...]
}
```

### HTML Report

Professional report with dark theme and QSL branding:

- Executive summary with risk metrics
- Visual risk distribution chart
- Sortable findings table
- Self-contained single file (no external dependencies)

---

## Default Exclusions

The following directories are excluded by default:

- `.git`, `.svn`, `.hg`
- `node_modules`
- `__pycache__`, `.pytest_cache`, `.mypy_cache`
- `.venv`, `venv`, `env`
- `dist`, `build`
- `.idea`, `.vscode`
- `vendor`, `third_party`

Add custom exclusions with `--exclude`:

```bash
crypto-scanner scan . --exclude "*.min.js" --exclude "legacy/"
```

---

## Development

### Setup Development Environment

```bash
git clone https://github.com/mbennett-labs/crypto-scanner.git
cd crypto-scanner
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/
pytest tests/ -v --cov=crypto_scanner
```

### Project Structure

```
crypto-scanner/
├── src/
│   └── crypto_scanner/
│       ├── __init__.py
│       ├── cli.py           # Typer CLI
│       ├── scanner.py       # Core scanning logic
│       ├── models.py        # Pydantic models
│       ├── patterns.py      # Regex patterns
│       ├── analyzers/       # File type analyzers
│       │   ├── base.py
│       │   ├── certificate.py
│       │   ├── config.py
│       │   └── source.py
│       └── reporters/       # Output generators
│           ├── json_reporter.py
│           └── html_reporter.py
├── tests/
│   ├── test_scanner.py
│   ├── test_analyzers.py
│   └── fixtures/
├── pyproject.toml
└── README.md
```

---

## Integration

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Crypto Vulnerability Scan
  run: |
    pip install crypto-scanner
    crypto-scanner scan ./src --output crypto-report.json

- name: Check for Critical Findings
  run: |
    CRITICAL=$(jq '.summary.critical_count' crypto-report.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: crypto-scanner
        name: Crypto Scanner
        entry: crypto-scanner scan . --output /dev/null
        language: system
        pass_filenames: false
```

---

## Why Quantum-Ready?

Quantum computers capable of breaking RSA and ECC are expected within 10-15 years. Organizations should begin transitioning now because:

1. **Harvest Now, Decrypt Later**: Adversaries may be collecting encrypted data today
2. **Migration Takes Time**: Large codebases need years to transition
3. **Compliance**: NIST PQC standards are now finalized
4. **Supply Chain**: Dependencies may contain vulnerable cryptography

Crypto Scanner helps you inventory your cryptographic usage as the first step toward quantum readiness.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## About Quantum Shield Labs

[Quantum Shield Labs](https://quantumshieldlabs.dev) provides enterprise quantum readiness assessments and post-quantum cryptography migration services.

- **Quantum Risk Assessments**
- **PQC Migration Planning**
- **Executive Briefings**
- **Developer Training**

Contact: [contact@quantumshieldlabs.dev](mailto:contact@quantumshieldlabs.dev)
