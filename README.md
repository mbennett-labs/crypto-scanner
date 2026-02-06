<p align="center">
  <img src="https://via.placeholder.com/600x150/1a1a2e/e94560?text=Crypto+Scanner" alt="Crypto Scanner Logo" />
</p>

<h1 align="center">Crypto Scanner</h1>

<p align="center">
  <strong>Scan your codebase for quantum-vulnerable cryptography before it's too late.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/crypto-scanner/"><img src="https://img.shields.io/pypi/v/crypto-scanner?color=blue&label=PyPI" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/crypto-scanner/"><img src="https://img.shields.io/pypi/dm/crypto-scanner?color=green&label=Downloads" alt="PyPI Downloads"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python 3.10+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/mbennett-labs/crypto-scanner/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#why-quantum-ready">Why Quantum-Ready?</a> •
  <a href="#usage">Usage</a> •
  <a href="#risk-classification">Risk Levels</a> •
  <a href="#cicd-integration">CI/CD</a> •
  <a href="#about-quantum-shield-labs">About</a>
</p>

---

## Overview

**Crypto Scanner** is a CLI tool that scans your codebase for cryptographic algorithms and generates quantum-vulnerability risk assessments. It analyzes source code, configuration files, and X.509 certificates to identify cryptography that will be broken by quantum computers.

Developed by [Quantum Shield Labs](https://quantumshieldlabs.dev) — helping organizations prepare for the post-quantum era.

---

## Why Quantum-Ready?

### The Quantum Threat Is Real

Cryptographically Relevant Quantum Computers (CRQCs) capable of breaking RSA and ECC are projected to emerge by **2033**. This isn't science fiction—it's a timeline that major governments and enterprises are actively preparing for.

### Harvest Now, Decrypt Later (HNDL)

Adversaries are already collecting encrypted data today with the intention of decrypting it once quantum computers become available. If your data has long-term value (healthcare records, financial data, trade secrets, government communications), it's already at risk.

### Why You Can't Wait

| Challenge | Reality |
|-----------|---------|
| **Migration complexity** | Large codebases take 3-5+ years to transition |
| **Supply chain depth** | Your dependencies contain vulnerable crypto you don't see |
| **Compliance mandates** | NIST PQC standards (ML-KEM, ML-DSA) are now finalized |
| **CNSA 2.0 deadline** | NSA requires quantum-resistant algorithms by 2033 |

### Shor's Algorithm: The Threat

Shor's algorithm, running on a sufficiently powerful quantum computer, can efficiently factor large integers and compute discrete logarithms. This breaks:

- **RSA** (all key sizes)
- **ECDSA/ECC** (all curves)
- **DH/ECDH** (key exchange)
- **DSA** (digital signatures)

### The First Step: Inventory

You can't migrate what you don't know you have. Crypto Scanner provides the cryptographic inventory that is the essential first step in any quantum readiness program.

> 📘 **Learn more**: Read the [Quantum Shield Labs Playbook](https://quantumshieldlabs.dev/playbook) for comprehensive migration guidance.

---

## Quick Start

Get your first quantum vulnerability scan in under 60 seconds:

```bash
# Install from PyPI
pip install crypto-scanner

# Scan your project
crypto-scanner scan .

# Generate an executive HTML report
crypto-scanner scan . --html --output quantum-risk-report.html
```

That's it. You now have a complete cryptographic inventory of your codebase.

---

## Installation

### From PyPI (Recommended)

```bash
pip install crypto-scanner
```

### From Source

```bash
git clone https://github.com/mbennett-labs/crypto-scanner.git
cd crypto-scanner
pip install -e .
```

### Requirements

- Python 3.10 or higher
- Works on Windows, macOS, and Linux

---

## Usage

### Basic Commands

```bash
# Scan a directory (JSON output to stdout)
crypto-scanner scan <directory>

# Show supported file types and risk classifications
crypto-scanner info

# Display version
crypto-scanner --version
```

### CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--html` | | Generate HTML report instead of JSON |
| `--output` | `-o` | Save report to file (instead of stdout) |
| `--verbose` | `-v` | Show detailed scanning progress |
| `--exclude` | `-e` | Additional exclude patterns (repeatable) |
| `--version` | `-V` | Show version and exit |

### Examples

```bash
# Scan with verbose output
crypto-scanner scan ./src --verbose

# Save JSON report to file
crypto-scanner scan . --output crypto-audit.json

# Generate branded HTML report for stakeholders
crypto-scanner scan . --html --output quantum-assessment.html

# Exclude specific directories
crypto-scanner scan . --exclude vendor --exclude legacy

# Exclude file patterns
crypto-scanner scan . --exclude "*.test.js" --exclude "*.spec.ts"

# Combine options
crypto-scanner scan ./backend -v --exclude node_modules -o report.json
```

### Default Exclusions

The following are automatically excluded to avoid scanning dependencies:

```
.git, .svn, .hg          # Version control
node_modules, vendor     # Package dependencies
__pycache__, .pytest_cache, .mypy_cache
.venv, venv, env         # Virtual environments
dist, build, out         # Build outputs
.idea, .vscode           # IDE directories
site-packages, third_party
```

---

## Risk Classification

### Critical — Quantum Vulnerable

Algorithms that will be completely broken by Shor's algorithm:

| Algorithm | Key Sizes | Quantum Impact | Recommended Action |
|-----------|-----------|----------------|-------------------|
| **RSA** | All (1024-4096+) | Completely broken | Migrate to ML-KEM + ML-DSA |
| **ECDSA/ECC** | All curves | Completely broken | Migrate to ML-DSA |
| **DH/ECDH** | All | Key exchange broken | Migrate to ML-KEM |
| **DSA** | All | Completely broken | Migrate to ML-DSA |

### High — Deprecated or Weak

Algorithms with known classical vulnerabilities:

| Algorithm | Issue | Recommended Action |
|-----------|-------|-------------------|
| **MD5** | Collision attacks, completely broken | Replace with SHA-3 or SHA-256 |
| **SHA-1** | Collision attacks demonstrated | Replace with SHA-256+ |
| **DES** | 56-bit key, trivially broken | Replace with AES-256 |
| **3DES** | Meet-in-the-middle attacks | Replace with AES-256 |
| **AES-128** | Grover's algorithm reduces security | Upgrade to AES-256 |

### Medium — Monitor

Algorithms that are currently secure but should be monitored:

| Algorithm | Status | Recommended Action |
|-----------|--------|-------------------|
| **SHA-256** | Secure, Grover reduces to 128-bit | Plan migration to SHA-3 |
| **SHA-384** | Secure | Monitor developments |
| **SHA-512** | Good quantum resistance | Monitor developments |
| **TLS 1.2** | Secure but aging | Prefer TLS 1.3 |

### Low — Adequate or Quantum-Resistant

Algorithms that provide adequate protection:

| Algorithm | Status | Notes |
|-----------|--------|-------|
| **AES-256** | Quantum-resistant | 128-bit post-quantum security |
| **ChaCha20** | Modern, secure | Good AES alternative |
| **SHA-3** | Latest NIST standard | Recommended for new projects |
| **ML-KEM** | Post-quantum (Kyber) | NIST standardized 2024 |
| **ML-DSA** | Post-quantum (Dilithium) | NIST standardized 2024 |

---

## Supported File Types

### Source Code

| Extension | Language |
|-----------|----------|
| `.py`, `.pyw` | Python |
| `.js`, `.mjs`, `.cjs` | JavaScript |
| `.ts`, `.tsx` | TypeScript |
| `.java` | Java |
| `.go` | Go |
| `.rs` | Rust |
| `.c`, `.h`, `.cpp`, `.hpp` | C/C++ |
| `.cs` | C# |
| `.rb` | Ruby |
| `.php` | PHP |
| `.swift` | Swift |
| `.kt`, `.kts` | Kotlin |
| `.scala` | Scala |

### Configuration Files

| Extension | Format |
|-----------|--------|
| `.yaml`, `.yml` | YAML |
| `.json` | JSON |
| `.toml` | TOML |
| `.ini`, `.cfg`, `.conf`, `.config` | INI/Config |
| `.env` | Environment variables |

### Certificates

| Extension | Format |
|-----------|--------|
| `.pem` | PEM encoded |
| `.crt`, `.cer`, `.cert` | Certificate |
| `.der` | DER encoded |

---

## Output Formats

### JSON Report

Default output format, ideal for automation and CI/CD pipelines:

```json
{
  "scan_directory": "/path/to/project",
  "scan_timestamp": "2026-02-06T10:30:00",
  "scanner_version": "0.1.0",
  "summary": {
    "total_files_scanned": 150,
    "total_findings": 23,
    "critical_count": 5,
    "high_count": 8,
    "medium_count": 7,
    "low_count": 3
  },
  "excluded_patterns": [".git", "node_modules", "..."],
  "findings": [
    {
      "file_path": "/path/to/auth.py",
      "line_number": 42,
      "algorithm": "RSA",
      "key_size": 2048,
      "risk_level": "critical",
      "description": "RSA key generation detected",
      "recommendation": "Plan migration to post-quantum algorithms (ML-KEM, ML-DSA)",
      "context": "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
    }
  ]
}
```

### HTML Report

Professional, self-contained report with Quantum Shield Labs branding:

- **Executive summary** with risk metrics at a glance
- **Visual risk distribution** chart
- **Sortable findings table** with filtering
- **Dark theme** optimized for readability
- **Single file** with no external dependencies (easy to share)

Generate with:
```bash
crypto-scanner scan . --html --output report.html
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Crypto Vulnerability Scan

on: [push, pull_request]

jobs:
  crypto-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Crypto Scanner
        run: pip install crypto-scanner

      - name: Run Crypto Scan
        run: crypto-scanner scan ./src --output crypto-report.json

      - name: Check for Critical Findings
        run: |
          CRITICAL=$(jq '.summary.critical_count' crypto-report.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Found $CRITICAL critical quantum-vulnerable algorithms!"
            jq '.findings[] | select(.risk_level == "critical")' crypto-report.json
            exit 1
          fi

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: crypto-vulnerability-report
          path: crypto-report.json
```

### GitLab CI

```yaml
crypto-scan:
  stage: security
  image: python:3.12
  script:
    - pip install crypto-scanner
    - crypto-scanner scan . --output crypto-report.json
    - |
      CRITICAL=$(jq '.summary.critical_count' crypto-report.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "Critical quantum-vulnerable cryptography detected!"
        exit 1
      fi
  artifacts:
    reports:
      dotenv: crypto-report.json
    paths:
      - crypto-report.json
    when: always
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: crypto-scanner
        name: Crypto Scanner
        entry: bash -c 'crypto-scanner scan . --output /tmp/crypto-scan.json && CRITICAL=$(jq ".summary.critical_count" /tmp/crypto-scan.json) && [ "$CRITICAL" -eq 0 ]'
        language: system
        pass_filenames: false
        always_run: true
```

### Simple Shell Script

```bash
#!/bin/bash
# crypto-check.sh - Fail if critical vulnerabilities found

set -e

crypto-scanner scan . --output /tmp/crypto-report.json

CRITICAL=$(jq '.summary.critical_count' /tmp/crypto-report.json)
HIGH=$(jq '.summary.high_count' /tmp/crypto-report.json)

echo "Scan complete: $CRITICAL critical, $HIGH high risk findings"

if [ "$CRITICAL" -gt 0 ]; then
    echo "FAILED: Critical quantum-vulnerable cryptography detected!"
    exit 1
fi
```

---

## Architecture

```
crypto-scanner/
├── src/crypto_scanner/
│   ├── cli.py              # Typer CLI interface
│   ├── scanner.py          # Core orchestration logic
│   ├── models.py           # Pydantic data models
│   ├── patterns.py         # 50+ regex detection patterns
│   ├── analyzers/          # File type analyzers
│   │   ├── base.py         # Abstract base class
│   │   ├── source.py       # Source code analyzer (14 languages)
│   │   ├── config.py       # Configuration file analyzer
│   │   └── certificate.py  # X.509 certificate analyzer
│   └── reporters/          # Output generators
│       ├── json_reporter.py
│       └── html_reporter.py
└── tests/                  # Comprehensive test suite
```

### How It Works

1. **Scanner** recursively walks the target directory, respecting exclusion patterns
2. **Analyzers** are dispatched based on file extension:
   - `SourceCodeAnalyzer` — Pattern matching across 14 programming languages
   - `ConfigAnalyzer` — YAML/JSON parsing + pattern matching for config files
   - `CertificateAnalyzer` — X.509 parsing to extract key algorithms and sizes
3. **Patterns** module contains 50+ regex patterns for cryptographic API detection
4. **Reporters** aggregate findings into JSON or HTML format

---

## Contributing

Contributions are welcome! Here's how to get started:

### Development Setup

```bash
git clone https://github.com/mbennett-labs/crypto-scanner.git
cd crypto-scanner
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=crypto_scanner --cov-report=html
```

### Adding New Patterns

Crypto patterns are defined in `src/crypto_scanner/patterns.py`. Each pattern includes:
- Regex pattern for detection
- Algorithm name
- Risk level (CRITICAL, HIGH, MEDIUM, LOW)
- Description and recommendation

### Pull Request Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-pattern`)
3. Add tests for new functionality
4. Ensure all tests pass (`pytest tests/ -v`)
5. Submit a pull request with a clear description

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## About Quantum Shield Labs

<p align="center">
  <a href="https://quantumshieldlabs.dev">
    <img src="https://via.placeholder.com/200x60/1a1a2e/e94560?text=QSL" alt="Quantum Shield Labs" />
  </a>
</p>

[**Quantum Shield Labs**](https://quantumshieldlabs.dev) helps organizations prepare for the post-quantum era with:

- **Quantum Risk Assessments** — Comprehensive cryptographic inventory and risk analysis
- **PQC Migration Planning** — Roadmaps for transitioning to quantum-resistant algorithms
- **Executive Briefings** — Board-level presentations on quantum risk
- **Developer Training** — Hands-on workshops for engineering teams

### Resources

- [Quantum Readiness Playbook](https://quantumshieldlabs.dev/playbook)
- [Blog](https://quantumshieldlabs.dev/blog)
- [Contact Us](mailto:contact@quantumshieldlabs.dev)

---

<p align="center">
  <sub>Built with care by <a href="https://quantumshieldlabs.dev">Quantum Shield Labs</a></sub>
</p>
