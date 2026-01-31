"""Tests for the scanner module."""

import tempfile
from pathlib import Path

import pytest

from crypto_scanner.models import RiskLevel
from crypto_scanner.scanner import CryptoScanner


class TestCryptoScanner:
    """Tests for CryptoScanner class."""

    def test_scanner_initialization(self):
        """Test scanner initializes with default excludes."""
        scanner = CryptoScanner()
        assert ".git" in scanner.exclude_patterns
        assert "node_modules" in scanner.exclude_patterns

    def test_scanner_custom_excludes(self):
        """Test scanner accepts custom exclude patterns."""
        scanner = CryptoScanner(exclude_patterns=["custom_dir"])
        assert "custom_dir" in scanner.exclude_patterns
        assert ".git" in scanner.exclude_patterns  # Still has defaults

    def test_scan_nonexistent_directory(self):
        """Test scanning nonexistent directory raises error."""
        scanner = CryptoScanner()
        with pytest.raises(FileNotFoundError):
            scanner.scan(Path("/nonexistent/path/12345"))

    def test_scan_file_not_directory(self, tmp_path):
        """Test scanning a file instead of directory raises error."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        scanner = CryptoScanner()
        with pytest.raises(NotADirectoryError):
            scanner.scan(test_file)

    def test_scan_empty_directory(self, tmp_path):
        """Test scanning empty directory returns empty report."""
        scanner = CryptoScanner()
        report = scanner.scan(tmp_path)

        assert report.summary.total_files_scanned == 0
        assert report.summary.total_findings == 0
        assert len(report.findings) == 0

    def test_scan_python_file_with_rsa(self, tmp_path):
        """Test scanning Python file with RSA import."""
        test_file = tmp_path / "crypto_test.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
""")

        scanner = CryptoScanner()
        report = scanner.scan(tmp_path)

        assert report.summary.total_files_scanned >= 1
        assert report.summary.critical_count > 0

        # Check for RSA findings
        rsa_findings = [f for f in report.findings if "RSA" in f.algorithm]
        assert len(rsa_findings) > 0
        assert rsa_findings[0].risk_level == RiskLevel.CRITICAL

    def test_scan_python_file_with_md5(self, tmp_path):
        """Test scanning Python file with MD5 usage."""
        test_file = tmp_path / "hash_test.py"
        test_file.write_text("""
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""")

        scanner = CryptoScanner()
        report = scanner.scan(tmp_path)

        assert report.summary.high_count > 0

        md5_findings = [f for f in report.findings if "MD5" in f.algorithm]
        assert len(md5_findings) > 0
        assert md5_findings[0].risk_level == RiskLevel.HIGH

    def test_scan_excludes_git_directory(self, tmp_path):
        """Test that .git directory is excluded."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        git_file = git_dir / "config.py"
        git_file.write_text("from cryptography import rsa")

        scanner = CryptoScanner()
        report = scanner.scan(tmp_path)

        # Should not find anything in .git
        git_findings = [f for f in report.findings if ".git" in f.file_path]
        assert len(git_findings) == 0

    def test_scan_file_method(self, tmp_path):
        """Test scanning a single file."""
        test_file = tmp_path / "single.py"
        test_file.write_text("import hashlib; hashlib.sha256(b'test')")

        scanner = CryptoScanner()
        findings = scanner.scan_file(test_file)

        assert len(findings) > 0

    def test_get_supported_extensions(self):
        """Test getting supported extensions."""
        scanner = CryptoScanner()
        extensions = scanner.get_supported_extensions()

        assert ".py" in extensions
        assert ".js" in extensions
        assert ".pem" in extensions
        assert ".yaml" in extensions


class TestProgressCallback:
    """Tests for progress callback functionality."""

    def test_progress_callback_called(self, tmp_path):
        """Test that progress callback is called for each file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        files_processed = []

        def callback(file_path):
            files_processed.append(file_path)

        scanner = CryptoScanner(progress_callback=callback)
        scanner.scan(tmp_path)

        assert len(files_processed) > 0
