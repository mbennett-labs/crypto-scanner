"""Analyzer for certificate files (.pem, .crt, .cer, .p12)."""

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from crypto_scanner.analyzers.base import BaseAnalyzer
from crypto_scanner.models import Finding, RiskLevel


class CertificateAnalyzer(BaseAnalyzer):
    """Analyzes X.509 certificates for cryptographic vulnerabilities."""

    supported_extensions = {".pem", ".crt", ".cer", ".cert", ".der"}

    def analyze(self, file_path: Path) -> list[Finding]:
        """Analyze a certificate file for quantum vulnerabilities."""
        findings: list[Finding] = []

        try:
            cert_data = file_path.read_bytes()
            cert = self._load_certificate(cert_data)

            if cert is None:
                return findings

            findings.extend(self._analyze_certificate(cert, file_path))

        except Exception:
            # Skip files that can't be parsed as certificates
            pass

        return findings

    def _load_certificate(self, cert_data: bytes) -> x509.Certificate | None:
        """Try to load a certificate from various formats."""
        # Try PEM format
        try:
            return x509.load_pem_x509_certificate(cert_data)
        except Exception:
            pass

        # Try DER format
        try:
            return x509.load_der_x509_certificate(cert_data)
        except Exception:
            pass

        return None

    def _analyze_certificate(self, cert: x509.Certificate, file_path: Path) -> list[Finding]:
        """Analyze a loaded certificate."""
        findings: list[Finding] = []
        str_path = str(file_path)

        # Get public key
        public_key = cert.public_key()

        # Analyze key algorithm and size
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            findings.append(Finding(
                file_path=str_path,
                algorithm="RSA",
                key_size=key_size,
                risk_level=RiskLevel.CRITICAL,
                description=f"RSA certificate with {key_size}-bit key",
                recommendation="Plan migration to post-quantum certificates. RSA is vulnerable to Shor's algorithm.",
                context=f"Subject: {cert.subject.rfc4514_string()}",
            ))

            # Also flag if key size is small
            if key_size < 3072:
                findings.append(Finding(
                    file_path=str_path,
                    algorithm="RSA",
                    key_size=key_size,
                    risk_level=RiskLevel.HIGH,
                    description=f"RSA key size {key_size} bits is below recommended minimum of 3072",
                    recommendation="Immediately upgrade to RSA-3072 or higher while planning post-quantum migration.",
                    context=f"Subject: {cert.subject.rfc4514_string()}",
                ))

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_size = public_key.key_size
            curve_name = public_key.curve.name
            findings.append(Finding(
                file_path=str_path,
                algorithm="ECDSA/ECC",
                key_size=key_size,
                risk_level=RiskLevel.CRITICAL,
                description=f"ECDSA certificate using {curve_name} ({key_size}-bit)",
                recommendation="Plan migration to post-quantum certificates. ECC is vulnerable to Shor's algorithm.",
                context=f"Subject: {cert.subject.rfc4514_string()}",
            ))

        elif isinstance(public_key, dsa.DSAPublicKey):
            key_size = public_key.key_size
            findings.append(Finding(
                file_path=str_path,
                algorithm="DSA",
                key_size=key_size,
                risk_level=RiskLevel.CRITICAL,
                description=f"DSA certificate with {key_size}-bit key",
                recommendation="DSA is deprecated and quantum-vulnerable. Migrate immediately.",
                context=f"Subject: {cert.subject.rfc4514_string()}",
            ))

        # Check signature algorithm
        sig_algorithm = cert.signature_algorithm_oid._name
        if "sha1" in sig_algorithm.lower():
            findings.append(Finding(
                file_path=str_path,
                algorithm="SHA-1",
                risk_level=RiskLevel.HIGH,
                description=f"Certificate uses deprecated SHA-1 signature algorithm: {sig_algorithm}",
                recommendation="Reissue certificate with SHA-256 or SHA-384 signature.",
                context=f"Subject: {cert.subject.rfc4514_string()}",
            ))
        elif "md5" in sig_algorithm.lower():
            findings.append(Finding(
                file_path=str_path,
                algorithm="MD5",
                risk_level=RiskLevel.HIGH,
                description=f"Certificate uses broken MD5 signature algorithm: {sig_algorithm}",
                recommendation="Immediately reissue certificate with SHA-256 or higher.",
                context=f"Subject: {cert.subject.rfc4514_string()}",
            ))

        # Check expiration
        now = datetime.now(timezone.utc)
        if cert.not_valid_after_utc < now:
            findings.append(Finding(
                file_path=str_path,
                algorithm="Certificate",
                risk_level=RiskLevel.HIGH,
                description=f"Certificate expired on {cert.not_valid_after_utc.isoformat()}",
                recommendation="Replace expired certificate immediately.",
                context=f"Subject: {cert.subject.rfc4514_string()}",
            ))

        return findings
