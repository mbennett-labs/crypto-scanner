"""Analyzer for configuration files (.conf, .yaml, .json, .env, etc.)."""

import json
import re
from pathlib import Path

import yaml

from crypto_scanner.analyzers.base import BaseAnalyzer
from crypto_scanner.models import Finding, RiskLevel
from crypto_scanner.patterns import CONFIG_PATTERNS, CRITICAL_PATTERNS, HIGH_PATTERNS


class ConfigAnalyzer(BaseAnalyzer):
    """Analyzes configuration files for cryptographic settings."""

    supported_extensions = {".conf", ".yaml", ".yml", ".json", ".env", ".ini", ".toml", ".cfg", ".config"}

    # Additional config-specific patterns
    SENSITIVE_KEY_PATTERNS = [
        (re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*\S+", re.IGNORECASE), "API Key"),
        (re.compile(r"(?:secret[_-]?key|secretkey)\s*[=:]\s*\S+", re.IGNORECASE), "Secret Key"),
        (re.compile(r"(?:private[_-]?key|privatekey)\s*[=:]\s*\S+", re.IGNORECASE), "Private Key"),
        (re.compile(r"(?:encryption[_-]?key|encryptionkey)\s*[=:]\s*\S+", re.IGNORECASE), "Encryption Key"),
        (re.compile(r"(?:jwt[_-]?secret|jwtsecret)\s*[=:]\s*\S+", re.IGNORECASE), "JWT Secret"),
    ]

    TLS_VERSION_PATTERNS = [
        (re.compile(r"SSLv[23]", re.IGNORECASE), "SSLv2/v3", RiskLevel.HIGH),
        (re.compile(r"TLSv1\.0", re.IGNORECASE), "TLSv1.0", RiskLevel.HIGH),
        (re.compile(r"TLSv1\.1", re.IGNORECASE), "TLSv1.1", RiskLevel.HIGH),
        (re.compile(r"TLSv1\.2", re.IGNORECASE), "TLSv1.2", RiskLevel.MEDIUM),
        (re.compile(r"TLSv1\.3", re.IGNORECASE), "TLSv1.3", RiskLevel.LOW),
    ]

    def analyze(self, file_path: Path) -> list[Finding]:
        """Analyze a configuration file for cryptographic settings."""
        findings: list[Finding] = []
        content = self._read_file_safely(file_path)

        if content is None:
            return findings

        str_path = str(file_path)

        # Line-by-line pattern matching
        findings.extend(self._analyze_patterns(content, str_path))

        # Check for sensitive key configurations
        findings.extend(self._check_sensitive_keys(content, str_path))

        # Check TLS versions
        findings.extend(self._check_tls_versions(content, str_path))

        # Parse structured configs for deeper analysis
        if file_path.suffix.lower() in {".yaml", ".yml"}:
            findings.extend(self._analyze_yaml(content, str_path))
        elif file_path.suffix.lower() == ".json":
            findings.extend(self._analyze_json(content, str_path))

        return findings

    def _analyze_patterns(self, content: str, file_path: str) -> list[Finding]:
        """Apply regex patterns to find crypto references."""
        findings: list[Finding] = []
        lines = content.splitlines()

        all_patterns = CRITICAL_PATTERNS + HIGH_PATTERNS + CONFIG_PATTERNS

        for line_num, line in enumerate(lines, start=1):
            for pattern in all_patterns:
                if pattern.pattern.search(line):
                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_num,
                        algorithm=pattern.algorithm,
                        key_size=pattern.key_size,
                        risk_level=pattern.risk_level,
                        description=pattern.description,
                        recommendation=pattern.recommendation,
                        context=line.strip()[:200],
                    ))

        return findings

    def _check_sensitive_keys(self, content: str, file_path: str) -> list[Finding]:
        """Check for cryptographic key configurations."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            for pattern, key_type in self.SENSITIVE_KEY_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_num,
                        algorithm=key_type,
                        risk_level=RiskLevel.MEDIUM,
                        description=f"{key_type} configuration detected",
                        recommendation="Document key location for quantum migration planning. Ensure keys are stored securely.",
                        context=self._redact_sensitive(line.strip()),
                    ))

        return findings

    def _check_tls_versions(self, content: str, file_path: str) -> list[Finding]:
        """Check for TLS/SSL version configurations."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            for pattern, version, risk in self.TLS_VERSION_PATTERNS:
                if pattern.search(line):
                    if risk == RiskLevel.HIGH:
                        desc = f"Deprecated {version} protocol detected"
                        rec = "Disable deprecated protocols. Use TLSv1.3 with TLSv1.2 as fallback."
                    elif risk == RiskLevel.MEDIUM:
                        desc = f"{version} protocol configured"
                        rec = "TLSv1.2 is acceptable but prefer TLSv1.3 where possible."
                    else:
                        desc = f"Modern {version} protocol detected"
                        rec = "Excellent! TLSv1.3 is the recommended protocol."

                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_num,
                        algorithm=version,
                        risk_level=risk,
                        description=desc,
                        recommendation=rec,
                        context=line.strip()[:200],
                    ))

        return findings

    def _analyze_yaml(self, content: str, file_path: str) -> list[Finding]:
        """Parse YAML and look for crypto configurations."""
        findings: list[Finding] = []

        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                findings.extend(self._analyze_dict_recursive(data, file_path, ""))
        except Exception:
            pass

        return findings

    def _analyze_json(self, content: str, file_path: str) -> list[Finding]:
        """Parse JSON and look for crypto configurations."""
        findings: list[Finding] = []

        try:
            data = json.loads(content)
            if isinstance(data, dict):
                findings.extend(self._analyze_dict_recursive(data, file_path, ""))
        except Exception:
            pass

        return findings

    def _analyze_dict_recursive(
        self, data: dict, file_path: str, path: str
    ) -> list[Finding]:
        """Recursively analyze dictionary for crypto-related keys."""
        findings: list[Finding] = []
        crypto_keywords = {"encryption", "cipher", "algorithm", "key", "secret", "certificate", "ssl", "tls", "crypto"}

        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            key_lower = key.lower()

            # Check if key name suggests crypto configuration
            if any(kw in key_lower for kw in crypto_keywords):
                if isinstance(value, str):
                    findings.append(Finding(
                        file_path=file_path,
                        algorithm="Configuration",
                        risk_level=RiskLevel.MEDIUM,
                        description=f"Cryptographic configuration at {current_path}",
                        recommendation="Document this configuration for quantum migration planning.",
                        context=f"{key}: {self._redact_sensitive(str(value)[:100])}",
                    ))

            # Recurse into nested dicts
            if isinstance(value, dict):
                findings.extend(self._analyze_dict_recursive(value, file_path, current_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(
                            self._analyze_dict_recursive(item, file_path, f"{current_path}[{i}]")
                        )

        return findings

    def _redact_sensitive(self, text: str) -> str:
        """Redact potentially sensitive values in context."""
        # Redact anything that looks like a key or secret
        redacted = re.sub(
            r'(["\']?)([A-Za-z0-9+/=_-]{20,})(["\']?)',
            r'\1[REDACTED]\3',
            text
        )
        return redacted
