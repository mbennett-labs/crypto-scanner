"""Analyzer for source code files (.py, .js, .ts, .java, .go, .rs, etc.)."""

from pathlib import Path

from crypto_scanner.analyzers.base import BaseAnalyzer
from crypto_scanner.models import Finding
from crypto_scanner.patterns import ALL_PATTERNS, get_patterns_for_extension


class SourceCodeAnalyzer(BaseAnalyzer):
    """Analyzes source code files for cryptographic usage."""

    supported_extensions = {
        ".py", ".pyw",          # Python
        ".js", ".mjs", ".cjs",  # JavaScript
        ".ts", ".tsx",          # TypeScript
        ".java",                # Java
        ".go",                  # Go
        ".rs",                  # Rust
        ".c", ".h",             # C
        ".cpp", ".hpp", ".cc", ".cxx",  # C++
        ".cs",                  # C#
        ".rb",                  # Ruby
        ".php",                 # PHP
        ".swift",              # Swift
        ".kt", ".kts",         # Kotlin
        ".scala",              # Scala
    }

    def analyze(self, file_path: Path) -> list[Finding]:
        """Analyze a source code file for cryptographic usage."""
        findings: list[Finding] = []
        content = self._read_file_safely(file_path)

        if content is None:
            return findings

        str_path = str(file_path)
        lines = content.splitlines()

        # Get patterns relevant to this file type
        patterns = get_patterns_for_extension(file_path.suffix)

        # Track which patterns we've already matched to avoid duplicates on same line
        seen_matches: set[tuple[int, str]] = set()

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and comments (basic heuristic)
            stripped = line.strip()
            if not stripped or self._is_comment(stripped, file_path.suffix):
                continue

            for pattern in patterns:
                match = pattern.pattern.search(line)
                if match:
                    # Create a key for deduplication
                    match_key = (line_num, pattern.algorithm)
                    if match_key in seen_matches:
                        continue
                    seen_matches.add(match_key)

                    # Get context (the matched line plus surrounding context)
                    context = self._get_line_context(content, line_num, context_lines=1)

                    findings.append(Finding(
                        file_path=str_path,
                        line_number=line_num,
                        algorithm=pattern.algorithm,
                        key_size=pattern.key_size,
                        risk_level=pattern.risk_level,
                        description=pattern.description,
                        recommendation=pattern.recommendation,
                        context=context[:500],  # Limit context length
                    ))

        return findings

    def _is_comment(self, line: str, extension: str) -> bool:
        """
        Basic heuristic to detect if a line is a comment.

        Note: This is a simple heuristic and won't catch all cases
        (e.g., multi-line comments, inline comments after code).
        """
        # Single-line comment starters by language
        single_comment_chars = {
            # Python, Ruby, PHP, Bash
            ".py": "#", ".pyw": "#", ".rb": "#", ".php": "#",
            # C-style languages
            ".js": "//", ".mjs": "//", ".cjs": "//",
            ".ts": "//", ".tsx": "//",
            ".java": "//",
            ".go": "//",
            ".rs": "//",
            ".c": "//", ".h": "//",
            ".cpp": "//", ".hpp": "//", ".cc": "//", ".cxx": "//",
            ".cs": "//",
            ".swift": "//",
            ".kt": "//", ".kts": "//",
            ".scala": "//",
        }

        comment_char = single_comment_chars.get(extension.lower())
        if comment_char and line.startswith(comment_char):
            return True

        # Also check for common docstring/block comment starts
        if line.startswith('"""') or line.startswith("'''"):
            return True
        if line.startswith("/*") or line.startswith("*"):
            return True

        return False
