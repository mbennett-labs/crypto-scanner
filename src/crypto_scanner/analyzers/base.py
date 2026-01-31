"""Base analyzer class for crypto scanning."""

from abc import ABC, abstractmethod
from pathlib import Path

from crypto_scanner.models import Finding


class BaseAnalyzer(ABC):
    """Abstract base class for file analyzers."""

    # File extensions this analyzer handles
    supported_extensions: set[str] = set()

    @classmethod
    def can_analyze(cls, file_path: Path) -> bool:
        """Check if this analyzer can handle the given file."""
        return file_path.suffix.lower() in cls.supported_extensions

    @abstractmethod
    def analyze(self, file_path: Path) -> list[Finding]:
        """
        Analyze a file and return cryptographic findings.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of Finding objects
        """
        pass

    def _read_file_safely(self, file_path: Path) -> str | None:
        """
        Safely read a file's contents with error handling.

        Returns:
            File contents as string, or None if unreadable
        """
        try:
            # Try UTF-8 first
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                # Fall back to latin-1
                return file_path.read_text(encoding="latin-1")
            except Exception:
                return None
        except Exception:
            return None

    def _get_line_context(self, content: str, line_number: int, context_lines: int = 1) -> str:
        """
        Get context around a specific line.

        Args:
            content: Full file content
            line_number: 1-indexed line number
            context_lines: Number of lines before/after to include

        Returns:
            Context snippet
        """
        lines = content.splitlines()
        start = max(0, line_number - 1 - context_lines)
        end = min(len(lines), line_number + context_lines)
        context = lines[start:end]
        return "\n".join(context)
