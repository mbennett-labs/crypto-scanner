"""Tests for analyzer modules."""

import tempfile
from pathlib import Path

import pytest

from crypto_scanner.analyzers import CertificateAnalyzer, ConfigAnalyzer, SourceCodeAnalyzer
from crypto_scanner.models import RiskLevel


class TestSourceCodeAnalyzer:
    """Tests for SourceCodeAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        return SourceCodeAnalyzer()

    def test_can_analyze_python(self, analyzer):
        """Test analyzer recognizes Python files."""
        assert analyzer.can_analyze(Path("test.py"))
        assert analyzer.can_analyze(Path("test.pyw"))

    def test_can_analyze_javascript(self, analyzer):
        """Test analyzer recognizes JavaScript files."""
        assert analyzer.can_analyze(Path("test.js"))
        assert analyzer.can_analyze(Path("test.mjs"))
        assert analyzer.can_analyze(Path("test.ts"))

    def test_cannot_analyze_unsupported(self, analyzer):
        """Test analyzer rejects unsupported files."""
        assert not analyzer.can_analyze(Path("test.txt"))
        assert not analyzer.can_analyze(Path("test.md"))

    def test_detect_rsa_import(self, analyzer, tmp_path):
        """Test detection of RSA import."""
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.asymmetric import rsa")

        findings = analyzer.analyze(test_file)
        rsa_findings = [f for f in findings if "RSA" in f.algorithm]

        assert len(rsa_findings) > 0
        assert rsa_findings[0].risk_level == RiskLevel.CRITICAL

    def test_detect_md5(self, analyzer, tmp_path):
        """Test detection of MD5 usage."""
        test_file = tmp_path / "test.py"
        test_file.write_text("import hashlib\nhashlib.md5(b'data')")

        findings = analyzer.analyze(test_file)
        md5_findings = [f for f in findings if "MD5" in f.algorithm]

        assert len(md5_findings) > 0
        assert md5_findings[0].risk_level == RiskLevel.HIGH

    def test_detect_sha256(self, analyzer, tmp_path):
        """Test detection of SHA-256 usage."""
        test_file = tmp_path / "test.py"
        test_file.write_text("hashlib.sha256(b'data')")

        findings = analyzer.analyze(test_file)
        sha_findings = [f for f in findings if "SHA-256" in f.algorithm]

        assert len(sha_findings) > 0
        assert sha_findings[0].risk_level == RiskLevel.MEDIUM

    def test_detect_aes_256(self, analyzer, tmp_path):
        """Test detection of AES-256."""
        test_file = tmp_path / "test.py"
        test_file.write_text("key_size = 256  # AES-256")

        findings = analyzer.analyze(test_file)
        aes_findings = [f for f in findings if "AES-256" in f.algorithm]

        assert len(aes_findings) > 0
        assert aes_findings[0].risk_level == RiskLevel.LOW

    def test_detect_java_rsa(self, analyzer, tmp_path):
        """Test detection of RSA in Java code."""
        test_file = tmp_path / "Test.java"
        test_file.write_text('KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");')

        findings = analyzer.analyze(test_file)
        rsa_findings = [f for f in findings if "RSA" in f.algorithm]

        assert len(rsa_findings) > 0
        assert rsa_findings[0].risk_level == RiskLevel.CRITICAL

    def test_line_numbers_correct(self, analyzer, tmp_path):
        """Test that line numbers are correctly reported."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# comment\n# another\nimport hashlib\nhashlib.md5(b'x')")

        findings = analyzer.analyze(test_file)
        md5_findings = [f for f in findings if "MD5" in f.algorithm]

        assert len(md5_findings) > 0
        assert md5_findings[0].line_number == 4


class TestConfigAnalyzer:
    """Tests for ConfigAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        return ConfigAnalyzer()

    def test_can_analyze_yaml(self, analyzer):
        """Test analyzer recognizes YAML files."""
        assert analyzer.can_analyze(Path("test.yaml"))
        assert analyzer.can_analyze(Path("test.yml"))

    def test_can_analyze_json(self, analyzer):
        """Test analyzer recognizes JSON files."""
        assert analyzer.can_analyze(Path("test.json"))

    def test_can_analyze_env(self, analyzer):
        """Test analyzer recognizes .env files."""
        # Note: .env has no extension, but test.env does
        assert analyzer.can_analyze(Path("test.env"))
        assert analyzer.can_analyze(Path("config.ini"))

    def test_detect_tls_version(self, analyzer, tmp_path):
        """Test detection of TLS version configuration."""
        test_file = tmp_path / "nginx.conf"
        test_file.write_text("ssl_protocols TLSv1.2 TLSv1.3;")

        findings = analyzer.analyze(test_file)

        assert len(findings) > 0
        tls_findings = [f for f in findings if "TLS" in f.algorithm]
        assert len(tls_findings) > 0

    def test_detect_deprecated_ssl(self, analyzer, tmp_path):
        """Test detection of deprecated SSL versions."""
        test_file = tmp_path / "config.conf"
        test_file.write_text("protocol = SSLv3")

        findings = analyzer.analyze(test_file)
        ssl_findings = [f for f in findings if "SSL" in f.algorithm]

        assert len(ssl_findings) > 0
        assert ssl_findings[0].risk_level == RiskLevel.HIGH

    def test_detect_api_key(self, analyzer, tmp_path):
        """Test detection of API key configuration."""
        test_file = tmp_path / ".env"
        test_file.write_text("API_KEY=sk_live_1234567890abcdef")

        findings = analyzer.analyze(test_file)
        key_findings = [f for f in findings if "API Key" in f.algorithm]

        assert len(key_findings) > 0
        assert key_findings[0].risk_level == RiskLevel.MEDIUM

    def test_yaml_parsing(self, analyzer, tmp_path):
        """Test YAML file parsing."""
        test_file = tmp_path / "config.yaml"
        test_file.write_text("""
security:
  encryption:
    algorithm: AES-256
    key_size: 256
""")

        findings = analyzer.analyze(test_file)
        # Should find something related to encryption config
        assert len(findings) > 0


class TestCertificateAnalyzer:
    """Tests for CertificateAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        return CertificateAnalyzer()

    def test_can_analyze_pem(self, analyzer):
        """Test analyzer recognizes PEM files."""
        assert analyzer.can_analyze(Path("cert.pem"))
        assert analyzer.can_analyze(Path("cert.crt"))
        assert analyzer.can_analyze(Path("cert.cer"))

    def test_cannot_analyze_non_cert(self, analyzer):
        """Test analyzer rejects non-certificate files."""
        assert not analyzer.can_analyze(Path("test.py"))
        assert not analyzer.can_analyze(Path("test.txt"))

    def test_invalid_cert_returns_empty(self, analyzer, tmp_path):
        """Test that invalid certificate data returns empty findings."""
        test_file = tmp_path / "invalid.pem"
        test_file.write_text("not a valid certificate")

        findings = analyzer.analyze(test_file)
        assert len(findings) == 0
