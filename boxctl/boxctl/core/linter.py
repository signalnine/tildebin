"""Script metadata linter."""

from dataclasses import dataclass, field
from pathlib import Path

from boxctl.core.metadata import parse_metadata, validate_metadata, MetadataError


@dataclass
class LintResult:
    """Result of linting a script."""

    path: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True if no errors."""
        return len(self.errors) == 0


def lint_script(path: Path) -> LintResult:
    """
    Lint a single script.

    Args:
        path: Path to the script file

    Returns:
        LintResult with errors and warnings
    """
    result = LintResult(path=path)

    try:
        content = path.read_text()
    except OSError as e:
        result.errors.append(f"Cannot read file: {e}")
        return result

    try:
        metadata = parse_metadata(content)
    except MetadataError as e:
        result.errors.append(str(e))
        return result

    if metadata is None:
        result.errors.append("No boxctl metadata header found")
        return result

    # Run validation for warnings
    warnings = validate_metadata(metadata)
    result.warnings.extend(warnings)

    return result


def lint_all(directory: Path) -> list[LintResult]:
    """
    Lint all Python scripts in a directory.

    Args:
        directory: Directory to search

    Returns:
        List of LintResult for each script
    """
    results = []

    for path in directory.rglob("*.py"):
        if path.is_file():
            result = lint_script(path)
            results.append(result)

    return results
