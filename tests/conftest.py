"""Shared test fixtures."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Add project root to path for script imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class MockContext:
    """Mock Context for testing scripts without real system access."""

    def __init__(
        self,
        tools_available: list[str] | None = None,
        command_outputs: dict[tuple, str | Exception] | None = None,
        file_contents: dict[str, str] | None = None,
        env: dict[str, str] | None = None,
    ):
        self.tools_available = set(tools_available or [])
        self.command_outputs = command_outputs or {}
        self.file_contents = file_contents or {}
        self.env = env or {}
        self.commands_run: list[list[str]] = []

    def check_tool(self, name: str) -> bool:
        """Check if tool is in mocked available list."""
        return name in self.tools_available

    def run(
        self,
        cmd: list[str],
        check: bool = False,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Return mocked command output."""
        self.commands_run.append(cmd)
        key = tuple(cmd)
        if key not in self.command_outputs:
            raise KeyError(f"No mock output for command: {cmd}")

        output = self.command_outputs[key]
        if isinstance(output, Exception):
            raise output

        # Allow passing CompletedProcess directly for more control (e.g., non-zero returncode)
        if isinstance(output, subprocess.CompletedProcess):
            return output

        return subprocess.CompletedProcess(
            cmd,
            returncode=0,
            stdout=output,
            stderr="",
        )

    def read_file(self, path: str) -> str:
        """Return mocked file content."""
        if path not in self.file_contents:
            raise FileNotFoundError(f"No mock content for: {path}")
        return self.file_contents[path]

    def file_exists(self, path: str) -> bool:
        """Check if path is in mocked files."""
        return path in self.file_contents

    def glob(self, pattern: str, root: str = ".") -> list[str]:
        """Return mocked glob results.

        Simulates Path(root).glob(pattern) behavior.
        Returns paths that start with root and match the pattern.
        For absolute patterns (starting with /), matches against file_contents.
        """
        from fnmatch import fnmatch

        results = set()

        # Handle absolute path patterns (e.g., "/proc/*/stat")
        if pattern.startswith("/"):
            for path in self.file_contents.keys():
                if fnmatch(path, pattern):
                    results.add(path)
            return sorted(results)

        # Normalize root for relative patterns
        if not root.endswith("/"):
            root = root + "/"

        for path in self.file_contents.keys():
            # Check if path is under root
            if not path.startswith(root):
                continue

            # Get the relative part after root
            relative = path[len(root):]

            # For patterns like "[0-9]*", we want to match immediate children
            # (like "1234/comm" should yield "/proc/1234" as a dir match)
            parts = relative.split("/")
            if not parts or not parts[0]:
                continue

            immediate_child = parts[0]

            # Check if immediate child matches the pattern
            if fnmatch(immediate_child, pattern):
                full_child_path = root.rstrip("/") + "/" + immediate_child
                results.add(full_child_path)

        return sorted(results)

    def get_env(self, key: str, default: str | None = None) -> str | None:
        """Return mocked environment variable."""
        return self.env.get(key, default)

    def cpu_count(self) -> int:
        """Return mocked CPU count."""
        return int(self.env.get("cpu_count", "1"))

    def readlink(self, path: str) -> str:
        """Return mocked symlink target.

        In mock mode, symlink targets are stored as file contents.
        Returns empty string if path not found (like real implementation).
        """
        return self.file_contents.get(path, "")

    def is_dir(self, path: str) -> bool:
        """Check if path is a directory.

        In mock mode, a path is a directory if any file_contents path
        starts with that path + "/".
        """
        path_with_slash = path.rstrip("/") + "/"
        return any(p.startswith(path_with_slash) for p in self.file_contents.keys())


@pytest.fixture
def mock_context():
    """Factory fixture for creating MockContext instances."""
    def _create(**kwargs) -> MockContext:
        return MockContext(**kwargs)
    return _create


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return FIXTURES_DIR


def load_fixture(category: str, name: str) -> str:
    """Load a fixture file by category and name."""
    fixture_path = FIXTURES_DIR / category / name
    if not fixture_path.exists():
        raise FileNotFoundError(f"Fixture not found: {fixture_path}")
    return fixture_path.read_text()


def load_json_fixture(category: str, name: str) -> dict[str, Any]:
    """Load a JSON fixture file."""
    content = load_fixture(category, name)
    return json.loads(content)
