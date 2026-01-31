"""JSON reporter for crypto scanner output."""

import json
from pathlib import Path

from crypto_scanner.models import ScanReport


class JSONReporter:
    """Generates JSON reports from scan results."""

    def __init__(self, pretty: bool = True):
        """
        Initialize the JSON reporter.

        Args:
            pretty: Whether to pretty-print JSON output
        """
        self.pretty = pretty

    def generate(self, report: ScanReport) -> str:
        """
        Generate a JSON report string.

        Args:
            report: ScanReport to convert

        Returns:
            JSON string representation
        """
        data = report.to_dict()

        if self.pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, ensure_ascii=False)

    def save(self, report: ScanReport, output_path: Path) -> None:
        """
        Save report to a JSON file.

        Args:
            report: ScanReport to save
            output_path: Path to output file
        """
        json_content = self.generate(report)
        output_path.write_text(json_content, encoding="utf-8")
