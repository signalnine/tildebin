"""Filesystem utilities for scripts."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxctl.core.context import Context


class FileError(Exception):
    """Error accessing a file."""

    pass


def read_file(
    path: str,
    context: "Context | None" = None,
    default: str | None = None,
) -> str:
    """
    Read file contents.

    Args:
        path: Path to file
        context: Execution context (for testing)
        default: Default value if file doesn't exist

    Returns:
        File contents

    Raises:
        FileError: If file doesn't exist and no default provided
    """
    if context is None:
        from boxctl.core.context import Context
        context = Context()

    try:
        return context.read_file(path)
    except FileNotFoundError:
        if default is not None:
            return default
        raise FileError(f"File not found: {path}")


def file_exists(
    path: str,
    context: "Context | None" = None,
) -> bool:
    """
    Check if file exists.

    Args:
        path: Path to check
        context: Execution context (for testing)

    Returns:
        True if file exists
    """
    if context is None:
        from boxctl.core.context import Context
        context = Context()

    return context.file_exists(path)


def glob_files(
    pattern: str,
    context: "Context | None" = None,
) -> list[str]:
    """
    Find files matching pattern.

    Args:
        pattern: Glob pattern
        context: Execution context (for testing)

    Returns:
        List of matching file paths
    """
    if context is None:
        from boxctl.core.context import Context
        context = Context()

    return context.glob(pattern)
