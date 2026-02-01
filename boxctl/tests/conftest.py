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
        """Return mocked glob results."""
        from fnmatch import fnmatch
        return [p for p in self.file_contents.keys() if fnmatch(p, pattern)]

    def get_env(self, key: str, default: str | None = None) -> str | None:
        """Return mocked environment variable."""
        return self.env.get(key, default)

    def cpu_count(self) -> int:
        """Return mocked CPU count."""
        return int(self.env.get("cpu_count", "1"))


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
