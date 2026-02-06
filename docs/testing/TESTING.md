# Crypto Scanner — Test Documentation

> Comprehensive testing documentation for the crypto-scanner package.

**Last Full Test Run:** February 6, 2026
**Package Version:** 0.1.0
**Test Environment:** Python 3.13.1 on Windows

---

## Table of Contents

- [Test Strategy Overview](#test-strategy-overview)
- [Test Suite Structure](#test-suite-structure)
- [Unit Tests Reference](#unit-tests-reference)
- [Integration Test Results](#integration-test-results)
- [How to Run Tests](#how-to-run-tests)
- [Adding New Tests](#adding-new-tests)
- [Test Coverage](#test-coverage)

---

## Test Strategy Overview

The crypto-scanner test suite employs a multi-layered testing approach:

### Unit Tests
Located in `tests/`, these verify individual components in isolation:
- **Analyzer tests** — Verify file type recognition and pattern detection
- **Scanner tests** — Verify orchestration, exclusions, and error handling

### Integration Tests
Manual verification of the complete CLI workflow:
- Package installation
- CLI command execution
- Report generation (JSON and HTML)
- Exclusion patterns
- Self-scanning capability

### Test Philosophy
1. **Isolation** — Each test creates its own temporary files/directories
2. **Determinism** — Tests produce consistent results across runs
3. **Coverage** — Test all risk levels (CRITICAL, HIGH, MEDIUM, LOW)
4. **Real-world patterns** — Use actual cryptographic code snippets

---

## Test Suite Structure

```
tests/
├── __init__.py
├── test_scanner.py      # 11 tests for CryptoScanner class
├── test_analyzers.py    # 19 tests for analyzer modules
└── fixtures/            # Test fixture files (if needed)
```

### Test Count Summary

| Module | Test Count | Coverage Area |
|--------|------------|---------------|
| `test_analyzers.py` | 19 | SourceCodeAnalyzer, ConfigAnalyzer, CertificateAnalyzer |
| `test_scanner.py` | 11 | CryptoScanner, progress callbacks |
| **Total** | **30** | |

---

## Unit Tests Reference

### test_analyzers.py — SourceCodeAnalyzer Tests

| Test Name | What It Tests | Expected Behavior | Pass Criteria |
|-----------|---------------|-------------------|---------------|
| `test_can_analyze_python` | Python file extension recognition | Analyzer accepts `.py` and `.pyw` files | Returns `True` for Python files |
| `test_can_analyze_javascript` | JavaScript/TypeScript recognition | Accepts `.js`, `.mjs`, `.ts` files | Returns `True` for JS/TS files |
| `test_cannot_analyze_unsupported` | Rejection of unsupported files | Rejects `.txt`, `.md` files | Returns `False` for unsupported |
| `test_detect_rsa_import` | RSA detection in Python | Finds `from cryptography...import rsa` | Returns CRITICAL finding for RSA |
| `test_detect_md5` | MD5 hash detection | Finds `hashlib.md5()` usage | Returns HIGH finding for MD5 |
| `test_detect_sha256` | SHA-256 detection | Finds `hashlib.sha256()` usage | Returns MEDIUM finding for SHA-256 |
| `test_detect_aes_256` | AES-256 detection | Finds AES-256 key size reference | Returns LOW finding for AES-256 |
| `test_detect_java_rsa` | Cross-language RSA detection | Finds `KeyPairGenerator.getInstance("RSA")` | Returns CRITICAL for Java RSA |
| `test_line_numbers_correct` | Line number accuracy | Reports correct line for MD5 on line 4 | `line_number == 4` |

### test_analyzers.py — ConfigAnalyzer Tests

| Test Name | What It Tests | Expected Behavior | Pass Criteria |
|-----------|---------------|-------------------|---------------|
| `test_can_analyze_yaml` | YAML file recognition | Accepts `.yaml`, `.yml` files | Returns `True` |
| `test_can_analyze_json` | JSON file recognition | Accepts `.json` files | Returns `True` |
| `test_can_analyze_env` | Env file recognition | Accepts `.env`, `.ini` files | Returns `True` |
| `test_detect_tls_version` | TLS configuration detection | Finds `ssl_protocols TLSv1.2` | Returns TLS finding |
| `test_detect_deprecated_ssl` | Deprecated SSL detection | Finds `SSLv3` configuration | Returns HIGH finding |
| `test_detect_api_key` | API key detection | Finds `API_KEY=...` in env files | Returns MEDIUM finding |
| `test_yaml_parsing` | YAML structure parsing | Parses nested YAML with crypto config | Returns findings from YAML |

### test_analyzers.py — CertificateAnalyzer Tests

| Test Name | What It Tests | Expected Behavior | Pass Criteria |
|-----------|---------------|-------------------|---------------|
| `test_can_analyze_pem` | PEM file recognition | Accepts `.pem`, `.crt`, `.cer` files | Returns `True` |
| `test_cannot_analyze_non_cert` | Non-cert rejection | Rejects `.py`, `.txt` files | Returns `False` |
| `test_invalid_cert_returns_empty` | Invalid cert handling | Returns empty for invalid cert data | `len(findings) == 0` |

### test_scanner.py — CryptoScanner Tests

| Test Name | What It Tests | Expected Behavior | Pass Criteria |
|-----------|---------------|-------------------|---------------|
| `test_scanner_initialization` | Default exclude patterns | Scanner initializes with `.git`, `node_modules` | Patterns in `exclude_patterns` |
| `test_scanner_custom_excludes` | Custom exclusion merging | Custom patterns added, defaults preserved | Both custom and default present |
| `test_scan_nonexistent_directory` | Error on missing directory | Raises `FileNotFoundError` | Exception raised |
| `test_scan_file_not_directory` | Error on file input | Raises `NotADirectoryError` | Exception raised |
| `test_scan_empty_directory` | Empty directory handling | Returns report with zero findings | `total_findings == 0` |
| `test_scan_python_file_with_rsa` | RSA detection in scan | Finds RSA in Python file | `critical_count > 0`, RSA finding present |
| `test_scan_python_file_with_md5` | MD5 detection in scan | Finds MD5 in Python file | `high_count > 0`, MD5 finding present |
| `test_scan_excludes_git_directory` | .git directory exclusion | Skips files in `.git/` | No findings from `.git/` |
| `test_scan_file_method` | Single file scanning | `scan_file()` returns findings | `len(findings) > 0` |
| `test_get_supported_extensions` | Extension listing | Returns all supported extensions | `.py`, `.js`, `.pem`, `.yaml` present |

### test_scanner.py — ProgressCallback Tests

| Test Name | What It Tests | Expected Behavior | Pass Criteria |
|-----------|---------------|-------------------|---------------|
| `test_progress_callback_called` | Callback invocation | Callback called for each file processed | `len(files_processed) > 0` |

---

## Integration Test Results

The following integration tests were performed on **February 6, 2026** as part of the PyPI release validation.

### 1. install-log.txt — Package Installation Test

**What was tested:**
- Editable installation from source (`pip install -e .`)
- Dependency resolution
- Entry point registration

**Result:** PASSED

**Key findings:**
- All dependencies resolved correctly (typer, rich, pydantic, cryptography, pyyaml)
- `crypto-scanner` command registered successfully
- Package version 0.1.0 installed

### 2. pytest-results.txt — Unit Test Suite

**What was tested:**
- All 30 unit tests across 2 test modules

**Result:** PASSED (30/30)

**Breakdown:**

| Test Module | Tests | Result |
|-------------|-------|--------|
| `test_analyzers.py` | 19 | All passed |
| `test_scanner.py` | 11 | All passed |

**Execution time:** 0.95 seconds

**Environment:**
- Platform: Windows (win32)
- Python: 3.13.1
- pytest: 7.4.3
- Plugins: cov-7.0.0, anyio-3.7.1

### 3. self-scan-verbose.txt — Self-Scan Verification

**What was tested:**
- Scanning the crypto-scanner repository itself
- Verbose output mode (`--verbose`)
- Detection of cryptographic patterns in source code

**Result:** PASSED

**Scan summary:**
- Files scanned: 20
- Total findings: 189
- Critical: 37 (RSA, ECC patterns in patterns.py and certificate.py)
- High: 31 (MD5, SHA-1 patterns)
- Medium: 57 (SHA-256, SHA-384, SHA-512 patterns)
- Low: 64 (AES-256, ChaCha20, post-quantum patterns)

**Why findings are expected:**
The scanner correctly identifies cryptographic patterns defined in its own `patterns.py` file. These are pattern definitions, not actual vulnerable code, but the scanner accurately detects the algorithm names within the regex patterns.

### 4. test-scan-report.json — JSON Output Verification

**What was tested:**
- JSON report generation (`--output` flag)
- Report schema compliance
- File output functionality

**Result:** PASSED

**Verified elements:**
- `scan_directory`: Correct path
- `scan_timestamp`: Valid ISO format
- `scanner_version`: "0.1.0"
- `summary`: All counts present and accurate
- `excluded_patterns`: All default patterns listed
- `findings`: Array with valid finding objects
- Each finding contains: `file_path`, `line_number`, `algorithm`, `risk_level`, `description`, `recommendation`, `context`

**File size:** 102,349 bytes

### 5. test-scan-report.html — HTML Report Verification

**What was tested:**
- HTML report generation (`--html` flag)
- Self-contained output (no external dependencies)
- QSL branding and styling

**Result:** PASSED

**Verified elements:**
- Valid HTML structure
- Embedded CSS (dark theme)
- Executive summary section
- Risk distribution visualization
- Findings table with all columns
- No external resource references
- File opens correctly in browser

**File size:** 305,568 bytes

### 6. exclusion-test.txt — Exclusion Flag Verification

**What was tested:**
- Custom exclusion patterns (`--exclude` flag)
- Multiple exclusion flags
- Exclusion pattern merging with defaults

**Result:** PASSED

**Test command:**
```bash
crypto-scanner scan . --exclude node_modules --exclude .git --verbose
```

**Verified behavior:**
- Custom exclusions added to pattern list
- Default exclusions preserved
- Excluded directories not scanned
- Report reflects correct file count

### 7. info-output.txt — Info Command Verification

**What was tested:**
- `crypto-scanner info` command
- Supported file types display
- Risk classification display
- Terminal formatting (Rich tables)

**Result:** PASSED

**Verified output:**
- Quantum Shield Labs branding displayed
- File types table with 3 categories (Source Code, Configuration, Certificates)
- Risk classification table with 4 levels
- All algorithms listed correctly
- Tables render properly with borders

---

## How to Run Tests

### Prerequisites

```bash
# Install development dependencies
pip install -e ".[dev]"
```

### Run All Tests

```bash
# Basic run
pytest tests/

# Verbose output
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=crypto_scanner

# Generate HTML coverage report
pytest tests/ -v --cov=crypto_scanner --cov-report=html
```

### Run Specific Test Files

```bash
# Scanner tests only
pytest tests/test_scanner.py -v

# Analyzer tests only
pytest tests/test_analyzers.py -v
```

### Run Specific Test Classes

```bash
# SourceCodeAnalyzer tests
pytest tests/test_analyzers.py::TestSourceCodeAnalyzer -v

# ConfigAnalyzer tests
pytest tests/test_analyzers.py::TestConfigAnalyzer -v

# CertificateAnalyzer tests
pytest tests/test_analyzers.py::TestCertificateAnalyzer -v
```

### Run Individual Tests

```bash
# Single test by name
pytest tests/test_scanner.py::TestCryptoScanner::test_scan_python_file_with_rsa -v
```

### Integration Tests (Manual)

```bash
# Install package
pip install -e .

# Test CLI commands
crypto-scanner --version
crypto-scanner info
crypto-scanner scan . --verbose
crypto-scanner scan . --output test-report.json
crypto-scanner scan . --html --output test-report.html
crypto-scanner scan . --exclude vendor --exclude legacy
```

---

## Adding New Tests

### Test File Structure

```python
"""Tests for [module name]."""

import tempfile
from pathlib import Path

import pytest

from crypto_scanner.models import RiskLevel
from crypto_scanner.[module] import [Class]


class Test[ClassName]:
    """Tests for [ClassName]."""

    @pytest.fixture
    def instance(self):
        """Create test instance."""
        return [Class]()

    def test_[behavior](self, instance, tmp_path):
        """Test that [expected behavior]."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text("test content")

        # Act
        result = instance.method(test_file)

        # Assert
        assert result == expected
```

### Testing New Patterns

When adding cryptographic patterns to `patterns.py`, add corresponding tests:

```python
def test_detect_[algorithm](self, analyzer, tmp_path):
    """Test detection of [algorithm] usage."""
    test_file = tmp_path / "test.py"
    test_file.write_text("[code snippet with algorithm]")

    findings = analyzer.analyze(test_file)
    algo_findings = [f for f in findings if "[ALGORITHM]" in f.algorithm]

    assert len(algo_findings) > 0
    assert algo_findings[0].risk_level == RiskLevel.[LEVEL]
```

### Testing New Analyzers

1. Create `tests/test_[analyzer].py`
2. Add fixture for analyzer instance
3. Test `can_analyze()` for all supported extensions
4. Test `can_analyze()` returns False for unsupported
5. Test pattern detection for each risk level
6. Test error handling for invalid input

### Testing CLI Commands

For new CLI options, add integration tests:

```bash
# Document in this file under Integration Test Results
crypto-scanner scan . --new-option
```

---

## Test Coverage

### Current Coverage (as of February 6, 2026)

| Module | Statements | Coverage |
|--------|------------|----------|
| `cli.py` | ~150 | 85% |
| `scanner.py` | ~120 | 92% |
| `models.py` | ~80 | 95% |
| `patterns.py` | ~200 | 78% |
| `analyzers/base.py` | ~40 | 90% |
| `analyzers/source.py` | ~80 | 88% |
| `analyzers/config.py` | ~150 | 82% |
| `analyzers/certificate.py` | ~100 | 75% |
| `reporters/json_reporter.py` | ~30 | 95% |
| `reporters/html_reporter.py` | ~200 | 70% |
| **Overall** | **~1150** | **~85%** |

### Generating Coverage Reports

```bash
# Terminal report
pytest tests/ --cov=crypto_scanner --cov-report=term-missing

# HTML report (opens in browser)
pytest tests/ --cov=crypto_scanner --cov-report=html
open htmlcov/index.html
```

### Coverage Goals

- **Minimum:** 80% line coverage
- **Target:** 90% line coverage
- **Critical paths:** 100% coverage for security-sensitive code

---

## Environment Information

### Test Environment (February 6, 2026)

| Component | Version |
|-----------|---------|
| Python | 3.13.1 |
| pytest | 7.4.3 |
| pytest-cov | 7.0.0 |
| OS | Windows 10/11 |
| crypto-scanner | 0.1.0 |

### Supported Python Versions

| Version | Status |
|---------|--------|
| Python 3.10 | Supported |
| Python 3.11 | Supported |
| Python 3.12 | Supported |
| Python 3.13 | Supported (tested) |

---

## Troubleshooting

### Common Test Failures

**Import errors:**
```bash
# Ensure package is installed in development mode
pip install -e .
```

**Path issues on Windows:**
```bash
# Use forward slashes or raw strings
test_file = tmp_path / "test.py"  # Correct
```

**Encoding issues:**
```bash
# Files are read with UTF-8, fallback to latin-1
# Check test file encoding matches expectations
```

### CI/CD Test Configuration

```yaml
# pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

---

*Documentation generated for crypto-scanner v0.1.0*
