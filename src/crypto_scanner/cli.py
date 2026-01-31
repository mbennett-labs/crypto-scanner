"""Command-line interface for crypto-scanner."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TextColumn
from rich.table import Table

from crypto_scanner import __version__
from crypto_scanner.models import RiskLevel
from crypto_scanner.reporters import HTMLReporter, JSONReporter
from crypto_scanner.scanner import CryptoScanner

app = typer.Typer(
    name="crypto-scanner",
    help="Scan directories for cryptographic usage and generate quantum-vulnerability risk assessments.",
    add_completion=False,
)

console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"crypto-scanner v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Crypto Scanner - Quantum Vulnerability Assessment Tool by Quantum Shield Labs."""
    pass


@app.command()
def scan(
    directory: Path = typer.Argument(
        ...,
        help="Directory to scan for cryptographic usage.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    html: bool = typer.Option(
        False,
        "--html",
        help="Generate HTML report instead of JSON.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save report to file. If not specified, prints to stdout.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed progress during scanning.",
    ),
    exclude: Optional[list[str]] = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Additional patterns to exclude (e.g., 'node_modules', '*.min.js').",
    ),
) -> None:
    """
    Scan a directory for cryptographic usage and vulnerabilities.

    Analyzes source code, configuration files, and certificates to identify
    cryptographic algorithms that may be vulnerable to quantum computing attacks.

    Examples:
        crypto-scanner scan .
        crypto-scanner scan /path/to/project --html --output report.html
        crypto-scanner scan . --exclude "*.test.js" --exclude "vendor"
    """
    # Print banner
    if verbose:
        console.print(
            Panel.fit(
                "[bold]Quantum Shield Labs[/bold]\n"
                "[dim]Cryptographic Vulnerability Scanner[/dim]",
                border_style="bright_magenta",
            )
        )
        console.print()

    # Setup progress callback for verbose mode
    file_count = 0

    def progress_callback(file_path: str) -> None:
        nonlocal file_count
        file_count += 1

    # Initialize scanner
    scanner = CryptoScanner(
        exclude_patterns=exclude,
        progress_callback=progress_callback if verbose else None,
    )

    # Run scan with progress indicator
    if verbose:
        console.print(f"Scanning {directory}...")
        report = scanner.scan(directory)
        console.print(f"Scanned {report.summary.total_files_scanned} files")
    else:
        report = scanner.scan(directory)

    # Generate report
    if html:
        reporter = HTMLReporter()
        report_content = reporter.generate(report)
        default_ext = ".html"
    else:
        reporter = JSONReporter(pretty=True)
        report_content = reporter.generate(report)
        default_ext = ".json"

    # Output report
    if output:
        output.write_text(report_content, encoding="utf-8")
        if verbose:
            console.print(f"\n[green]Report saved to:[/green] {output}")
    else:
        console.print(report_content)

    # Print summary in verbose mode
    if verbose:
        console.print()
        _print_summary(report.summary)


def _print_summary(summary) -> None:
    """Print a formatted summary table."""
    table = Table(title="Scan Summary", show_header=True, header_style="bold")
    table.add_column("Metric", style="dim")
    table.add_column("Count", justify="right")

    table.add_row("Files Scanned", str(summary.total_files_scanned))
    table.add_row("Total Findings", str(summary.total_findings))
    table.add_row("[red]Critical (Quantum-Vulnerable)[/red]", f"[red]{summary.critical_count}[/red]")
    table.add_row("[yellow]High (Deprecated)[/yellow]", f"[yellow]{summary.high_count}[/yellow]")
    table.add_row("[blue]Medium (Monitor)[/blue]", f"[blue]{summary.medium_count}[/blue]")
    table.add_row("[green]Low (Adequate)[/green]", f"[green]{summary.low_count}[/green]")

    console.print(table)

    # Print risk assessment
    if summary.critical_count > 0:
        console.print(
            "\n[red bold]! CRITICAL:[/red bold] Quantum-vulnerable algorithms detected. "
            "Plan migration to post-quantum cryptography."
        )
    elif summary.high_count > 0:
        console.print(
            "\n[yellow bold]! WARNING:[/yellow bold] Deprecated algorithms detected. "
            "Update to current standards."
        )
    elif summary.total_findings > 0:
        console.print(
            "\n[green]OK:[/green] No critical vulnerabilities found. "
            "Continue monitoring and plan for quantum readiness."
        )
    else:
        console.print("\n[green]OK:[/green] No cryptographic findings in scanned directory.")


@app.command()
def info() -> None:
    """Show information about supported file types and detected algorithms."""
    console.print(
        Panel.fit(
            "[bold]Quantum Shield Labs[/bold]\n"
            "[dim]Cryptographic Vulnerability Scanner[/dim]",
            border_style="bright_magenta",
        )
    )
    console.print()

    # Supported file types
    console.print("[bold]Supported File Types:[/bold]")
    console.print()

    file_table = Table(show_header=True, header_style="bold")
    file_table.add_column("Category")
    file_table.add_column("Extensions")

    file_table.add_row(
        "Source Code",
        ".py, .js, .ts, .java, .go, .rs, .c, .cpp, .cs, .rb, .php, .swift, .kt"
    )
    file_table.add_row(
        "Configuration",
        ".conf, .yaml, .yml, .json, .env, .ini, .toml, .cfg"
    )
    file_table.add_row(
        "Certificates",
        ".pem, .crt, .cer, .cert, .der"
    )

    console.print(file_table)
    console.print()

    # Risk levels
    console.print("[bold]Risk Classification:[/bold]")
    console.print()

    risk_table = Table(show_header=True, header_style="bold")
    risk_table.add_column("Level", style="bold")
    risk_table.add_column("Algorithms")
    risk_table.add_column("Action")

    risk_table.add_row(
        "[red]CRITICAL[/red]",
        "RSA, ECDSA/ECC, DH/ECDH, DSA",
        "Quantum-vulnerable. Plan migration to PQC."
    )
    risk_table.add_row(
        "[yellow]HIGH[/yellow]",
        "MD5, SHA-1, DES, 3DES, AES-128",
        "Deprecated or weak. Update immediately."
    )
    risk_table.add_row(
        "[blue]MEDIUM[/blue]",
        "SHA-256, SHA-384, SHA-512",
        "Acceptable. Plan future migration."
    )
    risk_table.add_row(
        "[green]LOW[/green]",
        "AES-256, ChaCha20, SHA-3, ML-KEM, ML-DSA",
        "Adequate or quantum-resistant."
    )

    console.print(risk_table)


if __name__ == "__main__":
    app()
