"""Data models for crypto scanner findings and reports."""

from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level classification for cryptographic findings."""

    CRITICAL = "critical"  # Quantum-vulnerable (RSA, ECDSA, DH, DSA)
    HIGH = "high"          # Weak/deprecated (AES-128, SHA-1, MD5, 3DES)
    MEDIUM = "medium"      # Acceptable but plan migration (SHA-256)
    LOW = "low"            # Quantum-resistant or adequate (AES-256, ChaCha20)

    def __lt__(self, other: "RiskLevel") -> bool:
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return order.index(self) < order.index(other)


class Finding(BaseModel):
    """Represents a single cryptographic finding."""

    file_path: str = Field(description="Path to the file containing the finding")
    line_number: int | None = Field(default=None, description="Line number of the finding")
    algorithm: str = Field(description="Cryptographic algorithm detected")
    key_size: int | None = Field(default=None, description="Key size in bits if applicable")
    risk_level: RiskLevel = Field(description="Risk classification")
    description: str = Field(description="Description of what was found")
    recommendation: str = Field(description="Recommended action to remediate")
    context: str | None = Field(default=None, description="Code snippet or context")

    def to_dict(self) -> dict:
        """Convert finding to dictionary for serialization."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "risk_level": self.risk_level.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "context": self.context,
        }


class ScanSummary(BaseModel):
    """Summary statistics for a scan."""

    total_files_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def add_finding(self, finding: Finding) -> None:
        """Update counts based on a finding."""
        self.total_findings += 1
        match finding.risk_level:
            case RiskLevel.CRITICAL:
                self.critical_count += 1
            case RiskLevel.HIGH:
                self.high_count += 1
            case RiskLevel.MEDIUM:
                self.medium_count += 1
            case RiskLevel.LOW:
                self.low_count += 1


class ScanReport(BaseModel):
    """Complete scan report with findings and metadata."""

    scan_directory: str = Field(description="Directory that was scanned")
    scan_timestamp: datetime = Field(default_factory=datetime.now)
    scanner_version: str = Field(default="0.1.0")
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[Finding] = Field(default_factory=list)
    excluded_patterns: list[str] = Field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report and update summary."""
        self.findings.append(finding)
        self.summary.add_finding(finding)

    def get_findings_by_risk(self, risk_level: RiskLevel) -> list[Finding]:
        """Get all findings of a specific risk level."""
        return [f for f in self.findings if f.risk_level == risk_level]

    def to_dict(self) -> dict:
        """Convert report to dictionary for serialization."""
        return {
            "scan_directory": self.scan_directory,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "scanner_version": self.scanner_version,
            "summary": {
                "total_files_scanned": self.summary.total_files_scanned,
                "total_findings": self.summary.total_findings,
                "critical_count": self.summary.critical_count,
                "high_count": self.summary.high_count,
                "medium_count": self.summary.medium_count,
                "low_count": self.summary.low_count,
            },
            "excluded_patterns": self.excluded_patterns,
            "findings": [f.to_dict() for f in self.findings],
        }
