"""Core scanning logic for crypto-scanner."""

import fnmatch
from pathlib import Path
from typing import Callable

from crypto_scanner.analyzers import CertificateAnalyzer, ConfigAnalyzer, SourceCodeAnalyzer
from crypto_scanner.analyzers.base import BaseAnalyzer
from crypto_scanner.models import Finding, ScanReport


class CryptoScanner:
    """
    Main scanner class that orchestrates file discovery and analysis.

    Recursively walks directories, dispatches files to appropriate analyzers,
    and aggregates findings into a report.
    """

    # Default patterns to exclude
    DEFAULT_EXCLUDES = {
        # Version control
        ".git",
        ".svn",
        ".hg",
        # Dependencies
        "node_modules",
        "vendor",
        "third_party",
        "site-packages",
        # Python
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        "*.egg-info",
        # Build outputs
        ".next",
        ".nuxt",
        ".output",
        "dist",
        "build",
        "out",
        "target",
        # IDE/Editor
        ".idea",
        ".vscode",
        # Environment files (often contains secrets)
        ".env",
    }

    def __init__(
        self,
        exclude_patterns: list[str] | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ):
        """
        Initialize the scanner.

        Args:
            exclude_patterns: Additional patterns to exclude from scanning
            progress_callback: Optional callback for progress updates
        """
        self.exclude_patterns = self.DEFAULT_EXCLUDES.copy()
        if exclude_patterns:
            self.exclude_patterns.update(exclude_patterns)

        self.progress_callback = progress_callback

        # Initialize analyzers
        self.analyzers: list[BaseAnalyzer] = [
            CertificateAnalyzer(),
            ConfigAnalyzer(),
            SourceCodeAnalyzer(),
        ]

    def scan(self, directory: Path) -> ScanReport:
        """
        Scan a directory for cryptographic usage.

        Args:
            directory: Path to directory to scan

        Returns:
            ScanReport with all findings
        """
        directory = Path(directory).resolve()

        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        report = ScanReport(
            scan_directory=str(directory),
            excluded_patterns=list(self.exclude_patterns),
        )

        # Recursively scan directory
        for file_path in self._walk_directory(directory):
            report.summary.total_files_scanned += 1

            if self.progress_callback:
                self.progress_callback(str(file_path))

            findings = self._analyze_file(file_path)
            for finding in findings:
                report.add_finding(finding)

        return report

    def scan_file(self, file_path: Path) -> list[Finding]:
        """
        Scan a single file for cryptographic usage.

        Args:
            file_path: Path to file to scan

        Returns:
            List of findings
        """
        file_path = Path(file_path).resolve()

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        return self._analyze_file(file_path)

    def _walk_directory(self, directory: Path):
        """
        Recursively walk directory, respecting exclude patterns.

        Yields:
            Path objects for each file to analyze
        """
        try:
            for item in directory.iterdir():
                # Check if item should be excluded
                if self._should_exclude(item):
                    continue

                if item.is_dir():
                    yield from self._walk_directory(item)
                elif item.is_file():
                    # Only yield files that have a supported extension
                    if self._has_supported_extension(item):
                        yield item
        except PermissionError:
            # Skip directories we can't access
            pass

    def _should_exclude(self, path: Path) -> bool:
        """Check if a path matches any exclude pattern."""
        name = path.name

        for pattern in self.exclude_patterns:
            # Direct name match
            if name == pattern:
                return True
            # Glob pattern match
            if fnmatch.fnmatch(name, pattern):
                return True
            # Check if any parent matches
            for parent in path.parents:
                if parent.name == pattern or fnmatch.fnmatch(parent.name, pattern):
                    return True

        return False

    def _has_supported_extension(self, file_path: Path) -> bool:
        """Check if any analyzer supports this file's extension."""
        return any(analyzer.can_analyze(file_path) for analyzer in self.analyzers)

    def _analyze_file(self, file_path: Path) -> list[Finding]:
        """
        Analyze a file using the appropriate analyzer(s).

        Args:
            file_path: Path to file to analyze

        Returns:
            List of findings from all applicable analyzers
        """
        findings: list[Finding] = []

        for analyzer in self.analyzers:
            if analyzer.can_analyze(file_path):
                try:
                    analyzer_findings = analyzer.analyze(file_path)
                    findings.extend(analyzer_findings)
                except Exception:
                    # Log error but continue scanning
                    pass

        return findings

    def get_supported_extensions(self) -> set[str]:
        """Get all file extensions supported by the scanner."""
        extensions: set[str] = set()
        for analyzer in self.analyzers:
            extensions.update(analyzer.supported_extensions)
        return extensions
