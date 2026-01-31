"""HTML reporter with dark theme and QSL branding."""

from datetime import datetime
from html import escape
from pathlib import Path

from crypto_scanner.models import RiskLevel, ScanReport


class HTMLReporter:
    """Generates self-contained HTML reports with dark theme and QSL branding."""

    # QSL brand colors
    COLORS = {
        "bg_primary": "#1a1a2e",
        "bg_secondary": "#16213e",
        "bg_tertiary": "#0f3460",
        "text_primary": "#eaeaea",
        "text_secondary": "#a0a0a0",
        "accent": "#e94560",
        "critical": "#e94560",
        "high": "#ff6b35",
        "medium": "#ffc107",
        "low": "#4caf50",
        "border": "#2a2a4a",
    }

    def generate(self, report: ScanReport) -> str:
        """
        Generate a self-contained HTML report.

        Args:
            report: ScanReport to convert

        Returns:
            HTML string
        """
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Vulnerability Assessment Report</title>
    <style>
{self._get_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._render_header(report)}
        {self._render_summary(report)}
        {self._render_risk_chart(report)}
        {self._render_findings(report)}
        {self._render_footer()}
    </div>
</body>
</html>"""

    def save(self, report: ScanReport, output_path: Path) -> None:
        """
        Save report to an HTML file.

        Args:
            report: ScanReport to save
            output_path: Path to output file
        """
        html_content = self.generate(report)
        output_path.write_text(html_content, encoding="utf-8")

    def _get_styles(self) -> str:
        """Generate CSS styles."""
        return f"""
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: {self.COLORS['bg_primary']};
            color: {self.COLORS['text_primary']};
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 2px solid {self.COLORS['border']};
            margin-bottom: 2rem;
        }}

        .logo {{
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, {self.COLORS['accent']}, #ff6b35);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}

        .subtitle {{
            color: {self.COLORS['text_secondary']};
            font-size: 1.1rem;
        }}

        .meta {{
            margin-top: 1rem;
            font-size: 0.9rem;
            color: {self.COLORS['text_secondary']};
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}

        .summary-card {{
            background: {self.COLORS['bg_secondary']};
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid {self.COLORS['border']};
        }}

        .summary-card.critical {{
            border-left: 4px solid {self.COLORS['critical']};
        }}

        .summary-card.high {{
            border-left: 4px solid {self.COLORS['high']};
        }}

        .summary-card.medium {{
            border-left: 4px solid {self.COLORS['medium']};
        }}

        .summary-card.low {{
            border-left: 4px solid {self.COLORS['low']};
        }}

        .summary-value {{
            font-size: 2.5rem;
            font-weight: 700;
        }}

        .summary-label {{
            color: {self.COLORS['text_secondary']};
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
            margin-top: 0.5rem;
        }}

        .critical .summary-value {{ color: {self.COLORS['critical']}; }}
        .high .summary-value {{ color: {self.COLORS['high']}; }}
        .medium .summary-value {{ color: {self.COLORS['medium']}; }}
        .low .summary-value {{ color: {self.COLORS['low']}; }}

        .risk-chart {{
            background: {self.COLORS['bg_secondary']};
            border-radius: 12px;
            padding: 1.5rem;
            margin: 2rem 0;
            border: 1px solid {self.COLORS['border']};
        }}

        .chart-bar {{
            display: flex;
            align-items: center;
            margin: 1rem 0;
        }}

        .chart-label {{
            width: 100px;
            font-size: 0.9rem;
            text-transform: uppercase;
        }}

        .chart-bar-container {{
            flex: 1;
            height: 24px;
            background: {self.COLORS['bg_tertiary']};
            border-radius: 4px;
            overflow: hidden;
            margin: 0 1rem;
        }}

        .chart-bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s ease;
        }}

        .chart-bar-fill.critical {{ background: {self.COLORS['critical']}; }}
        .chart-bar-fill.high {{ background: {self.COLORS['high']}; }}
        .chart-bar-fill.medium {{ background: {self.COLORS['medium']}; }}
        .chart-bar-fill.low {{ background: {self.COLORS['low']}; }}

        .chart-count {{
            width: 40px;
            text-align: right;
            font-weight: 600;
        }}

        section {{
            margin: 2rem 0;
        }}

        h2 {{
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid {self.COLORS['border']};
        }}

        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            background: {self.COLORS['bg_secondary']};
            border-radius: 12px;
            overflow: hidden;
        }}

        .findings-table th,
        .findings-table td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid {self.COLORS['border']};
        }}

        .findings-table th {{
            background: {self.COLORS['bg_tertiary']};
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }}

        .findings-table tr:hover {{
            background: {self.COLORS['bg_tertiary']};
        }}

        .risk-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .risk-badge.critical {{
            background: rgba(233, 69, 96, 0.2);
            color: {self.COLORS['critical']};
        }}

        .risk-badge.high {{
            background: rgba(255, 107, 53, 0.2);
            color: {self.COLORS['high']};
        }}

        .risk-badge.medium {{
            background: rgba(255, 193, 7, 0.2);
            color: {self.COLORS['medium']};
        }}

        .risk-badge.low {{
            background: rgba(76, 175, 80, 0.2);
            color: {self.COLORS['low']};
        }}

        .file-path {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.85rem;
            color: {self.COLORS['text_secondary']};
            word-break: break-all;
        }}

        .context {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.8rem;
            background: {self.COLORS['bg_tertiary']};
            padding: 0.5rem;
            border-radius: 4px;
            white-space: pre-wrap;
            word-break: break-all;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .recommendation {{
            font-size: 0.85rem;
            color: {self.COLORS['text_secondary']};
        }}

        footer {{
            text-align: center;
            padding: 2rem 0;
            margin-top: 2rem;
            border-top: 2px solid {self.COLORS['border']};
            color: {self.COLORS['text_secondary']};
            font-size: 0.9rem;
        }}

        footer a {{
            color: {self.COLORS['accent']};
            text-decoration: none;
        }}

        footer a:hover {{
            text-decoration: underline;
        }}

        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: {self.COLORS['text_secondary']};
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}

            .summary-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .findings-table {{
                font-size: 0.85rem;
            }}

            .findings-table th,
            .findings-table td {{
                padding: 0.75rem 0.5rem;
            }}
        }}
        """

    def _render_header(self, report: ScanReport) -> str:
        """Render the report header."""
        scan_time = report.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"""
        <header>
            <div class="logo">Quantum Shield Labs</div>
            <div class="subtitle">Cryptographic Vulnerability Assessment Report</div>
            <div class="meta">
                <div>Scanned: <strong>{escape(report.scan_directory)}</strong></div>
                <div>Generated: {scan_time} | Scanner v{report.scanner_version}</div>
            </div>
        </header>
        """

    def _render_summary(self, report: ScanReport) -> str:
        """Render the summary cards."""
        s = report.summary
        return f"""
        <section>
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-value">{s.total_files_scanned}</div>
                    <div class="summary-label">Files Scanned</div>
                </div>
                <div class="summary-card critical">
                    <div class="summary-value">{s.critical_count}</div>
                    <div class="summary-label">Critical (Quantum-Vulnerable)</div>
                </div>
                <div class="summary-card high">
                    <div class="summary-value">{s.high_count}</div>
                    <div class="summary-label">High (Deprecated)</div>
                </div>
                <div class="summary-card medium">
                    <div class="summary-value">{s.medium_count}</div>
                    <div class="summary-label">Medium (Monitor)</div>
                </div>
                <div class="summary-card low">
                    <div class="summary-value">{s.low_count}</div>
                    <div class="summary-label">Low (Adequate)</div>
                </div>
            </div>
        </section>
        """

    def _render_risk_chart(self, report: ScanReport) -> str:
        """Render the risk distribution chart."""
        s = report.summary
        total = max(s.total_findings, 1)  # Avoid division by zero

        def pct(count: int) -> str:
            return f"{(count / total) * 100:.1f}%"

        return f"""
        <section>
            <h2>Risk Distribution</h2>
            <div class="risk-chart">
                <div class="chart-bar">
                    <span class="chart-label">Critical</span>
                    <div class="chart-bar-container">
                        <div class="chart-bar-fill critical" style="width: {pct(s.critical_count)}"></div>
                    </div>
                    <span class="chart-count">{s.critical_count}</span>
                </div>
                <div class="chart-bar">
                    <span class="chart-label">High</span>
                    <div class="chart-bar-container">
                        <div class="chart-bar-fill high" style="width: {pct(s.high_count)}"></div>
                    </div>
                    <span class="chart-count">{s.high_count}</span>
                </div>
                <div class="chart-bar">
                    <span class="chart-label">Medium</span>
                    <div class="chart-bar-container">
                        <div class="chart-bar-fill medium" style="width: {pct(s.medium_count)}"></div>
                    </div>
                    <span class="chart-count">{s.medium_count}</span>
                </div>
                <div class="chart-bar">
                    <span class="chart-label">Low</span>
                    <div class="chart-bar-container">
                        <div class="chart-bar-fill low" style="width: {pct(s.low_count)}"></div>
                    </div>
                    <span class="chart-count">{s.low_count}</span>
                </div>
            </div>
        </section>
        """

    def _render_findings(self, report: ScanReport) -> str:
        """Render the findings table."""
        if not report.findings:
            return """
            <section>
                <h2>Findings</h2>
                <div class="no-findings">
                    <p>No cryptographic findings detected in the scanned directory.</p>
                </div>
            </section>
            """

        # Sort findings by risk level (critical first)
        sorted_findings = sorted(
            report.findings,
            key=lambda f: [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW].index(f.risk_level)
        )

        rows = []
        for f in sorted_findings:
            location = escape(f.file_path)
            if f.line_number:
                location += f":{f.line_number}"

            context_html = ""
            if f.context:
                context_html = f'<div class="context">{escape(f.context[:200])}</div>'

            rows.append(f"""
                <tr>
                    <td><span class="risk-badge {f.risk_level.value}">{f.risk_level.value}</span></td>
                    <td><strong>{escape(f.algorithm)}</strong></td>
                    <td class="file-path">{location}</td>
                    <td>{escape(f.description)}</td>
                    <td class="recommendation">{escape(f.recommendation)}</td>
                </tr>
            """)

        return f"""
        <section>
            <h2>Detailed Findings ({len(report.findings)} total)</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Algorithm</th>
                        <th>Location</th>
                        <th>Description</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </section>
        """

    def _render_footer(self) -> str:
        """Render the report footer."""
        year = datetime.now().year
        return f"""
        <footer>
            <p>Generated by <strong>Crypto Scanner</strong> |
               <a href="https://quantumshieldlabs.dev">Quantum Shield Labs</a></p>
            <p>&copy; {year} Quantum Shield Labs. All rights reserved.</p>
            <p style="margin-top: 1rem; font-size: 0.8rem;">
                This report identifies cryptographic algorithms that may be vulnerable to quantum computing attacks.
                Plan your migration to post-quantum cryptography today.
            </p>
        </footer>
        """
