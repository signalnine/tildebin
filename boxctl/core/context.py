"""Execution context for testability."""

import os
import shutil
import subprocess
from pathlib import Path


class Context:
    """
    Wraps external calls for testability.

    In production: executes real commands
    In tests: can be replaced with MockContext
    """

    def check_tool(self, name: str) -> bool:
        """Check if a tool exists in PATH."""
        return shutil.which(name) is not None

    def run(
        self,
        cmd: list[str],
        check: bool = False,
        timeout: int | None = 60,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """
        Run a command and return result.

        Args:
            cmd: Command and arguments as list
            check: Raise on non-zero exit code
            timeout: Timeout in seconds
            **kwargs: Additional subprocess.run arguments

        Returns:
            CompletedProcess with stdout, stderr, returncode
        """
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
            **kwargs,
        )

    def read_file(self, path: str) -> str:
        """Read file contents."""
        return Path(path).read_text()

    def file_exists(self, path: str) -> bool:
        """Check if file exists."""
        return Path(path).exists()

    def glob(self, pattern: str, root: str = ".") -> list[str]:
        """Find files matching pattern."""
        return [str(p) for p in Path(root).glob(pattern)]

    def get_env(self, key: str, default: str | None = None) -> str | None:
        """Get environment variable."""
        return os.environ.get(key, default)

    def cpu_count(self) -> int:
        """Get CPU count."""
        return os.cpu_count() or 1
