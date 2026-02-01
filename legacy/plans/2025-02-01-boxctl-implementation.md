# boxctl Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a unified CLI for discovering, running, and monitoring ~200 baremetal/k8s utility scripts with a bundled Python runtime.

**Architecture:** Bundled python-build-standalone runtime with external scripts. Core framework handles discovery, execution, logging. Scripts use Context injection for testability. User overrides take precedence over bundled scripts.

**Tech Stack:** Python 3.11 (bundled via python-build-standalone), PyYAML, pytest, GitHub Actions

---

## Phase 1: Project Setup & Core Framework

### Task 1.0: Constraints & Dependencies

**Key Constraints (from validation):**

1. **Script dependencies**: Scripts MUST only use stdlib + PyYAML. Any script needing external packages (kubernetes, requests, etc.) must shell out to system tools instead. This keeps the bundle size manageable and avoids dependency hell.

2. **Linux-only**: Initial release targets Linux x86_64 only. ARM64 support in Phase 6.

3. **Deferred features**: Runbooks and scheduler moved to Phase 7 (future). Core functionality first.

---

### Task 1.1: Initialize Project Structure

**Files:**
- Create: `boxctl/boxctl/__init__.py`
- Create: `boxctl/boxctl/__main__.py`
- Create: `boxctl/pyproject.toml`
- Create: `boxctl/README.md`

**Step 1: Create project directory structure**

```bash
mkdir -p boxctl/boxctl/core
mkdir -p boxctl/tests/core
mkdir -p boxctl/tests/fixtures
mkdir -p boxctl/scripts/baremetal
mkdir -p boxctl/scripts/k8s
mkdir -p boxctl/profiles
```

**Step 2: Create pyproject.toml**

```toml
# boxctl/pyproject.toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "boxctl"
version = "0.1.0"
description = "Unified CLI for baremetal and Kubernetes utility scripts"
requires-python = ">=3.11"
dependencies = [
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
]

[project.scripts]
boxctl = "boxctl.cli:main"

[tool.coverage.run]
source = ["boxctl"]
branch = true

[tool.coverage.report]
fail_under = 80
exclude_lines = [
    "pragma: no cover",
    "if __name__ == .__main__.:",
    "raise NotImplementedError",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--strict-markers -v"
markers = [
    "integration: marks tests as integration tests",
]
```

**Step 3: Create package init**

```python
# boxctl/boxctl/__init__.py
"""boxctl - Unified CLI for baremetal and Kubernetes utility scripts."""

__version__ = "0.1.0"
```

**Step 4: Create main entry point**

```python
# boxctl/boxctl/__main__.py
"""Allow running as python -m boxctl."""

from boxctl.cli import main

if __name__ == "__main__":
    main()
```

**Step 5: Commit**

```bash
git add boxctl/
git commit -m "feat: initialize boxctl project structure"
```

---

### Task 1.2: Implement Output Helper

**Files:**
- Create: `boxctl/boxctl/core/output.py`
- Create: `boxctl/tests/core/test_output.py`

**Step 1: Write failing tests for Output**

```python
# boxctl/tests/core/test_output.py
"""Tests for Output helper."""

import json
import pytest
from boxctl.core.output import Output


class TestOutput:
    """Tests for structured output helper."""

    def test_emit_stores_data(self):
        """emit() stores data for later retrieval."""
        output = Output()
        output.emit({"disks": [{"name": "sda", "status": "ok"}]})
        assert output.data["disks"][0]["name"] == "sda"

    def test_error_stores_message(self):
        """error() stores error messages."""
        output = Output()
        output.error("smartctl not found")
        assert "smartctl not found" in output.errors

    def test_warning_stores_message(self):
        """warning() stores warning messages."""
        output = Output()
        output.warning("disk degraded")
        assert "disk degraded" in output.warnings

    def test_json_format(self):
        """to_json() returns valid JSON string."""
        output = Output()
        output.emit({"test": "value"})
        result = output.to_json()
        parsed = json.loads(result)
        assert parsed["test"] == "value"

    def test_plain_format_with_data(self):
        """to_plain() formats data as readable text."""
        output = Output()
        output.emit({"status": "ok", "count": 5})
        result = output.to_plain()
        assert "status" in result
        assert "ok" in result

    def test_summary_property(self):
        """summary returns first line of plain output."""
        output = Output()
        output.emit({"status": "ok"})
        output.set_summary("All checks passed")
        assert output.summary == "All checks passed"
```

**Step 2: Run tests to verify they fail**

```bash
cd boxctl && python -m pytest tests/core/test_output.py -v
```

Expected: FAIL with "ModuleNotFoundError: No module named 'boxctl.core.output'"

**Step 3: Implement Output class**

```python
# boxctl/boxctl/core/output.py
"""Structured output helper for scripts."""

import json
from typing import Any


class Output:
    """Helper for structured script output."""

    def __init__(self):
        self.data: dict[str, Any] = {}
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self._summary: str | None = None

    def emit(self, data: dict[str, Any]) -> None:
        """Store structured output data."""
        self.data.update(data)

    def error(self, message: str) -> None:
        """Record an error message."""
        self.errors.append(message)

    def warning(self, message: str) -> None:
        """Record a warning message."""
        self.warnings.append(message)

    def set_summary(self, summary: str) -> None:
        """Set a one-line summary."""
        self._summary = summary

    @property
    def summary(self) -> str:
        """Get summary or generate from data."""
        if self._summary:
            return self._summary
        if self.errors:
            return f"Error: {self.errors[0]}"
        if self.warnings:
            return f"Warning: {self.warnings[0]}"
        return "ok"

    def to_json(self) -> str:
        """Return data as JSON string."""
        return json.dumps(self.data, indent=2, default=str)

    def to_plain(self) -> str:
        """Return data as plain text."""
        lines = []
        for key, value in self.data.items():
            if isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"  - {item}")
                    else:
                        lines.append(f"  - {item}")
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)
```

**Step 4: Create core __init__.py**

```python
# boxctl/boxctl/core/__init__.py
"""Core boxctl functionality."""

from boxctl.core.output import Output

__all__ = ["Output"]
```

**Step 5: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/core/test_output.py -v
```

Expected: All 6 tests PASS

**Step 6: Commit**

```bash
git add boxctl/boxctl/core/ boxctl/tests/core/
git commit -m "feat(core): add Output helper for structured script output"
```

---

### Task 1.3: Implement Context for Testability

**Files:**
- Create: `boxctl/boxctl/core/context.py`
- Create: `boxctl/tests/core/test_context.py`
- Create: `boxctl/tests/conftest.py`

**Step 1: Write failing tests for Context**

```python
# boxctl/tests/core/test_context.py
"""Tests for Context execution wrapper."""

import subprocess
import pytest
from boxctl.core.context import Context


class TestContext:
    """Tests for execution context."""

    def test_check_tool_finds_existing(self):
        """check_tool returns True for existing tools."""
        ctx = Context()
        # 'ls' exists on all Unix systems
        assert ctx.check_tool("ls") is True

    def test_check_tool_missing(self):
        """check_tool returns False for missing tools."""
        ctx = Context()
        assert ctx.check_tool("nonexistent_tool_xyz") is False

    def test_run_executes_command(self):
        """run() executes command and returns result."""
        ctx = Context()
        result = ctx.run(["echo", "hello"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_run_captures_stderr(self):
        """run() captures stderr output."""
        ctx = Context()
        result = ctx.run(["ls", "/nonexistent_path_xyz"], check=False)
        assert result.returncode != 0
        assert result.stderr  # Should have error message

    def test_read_file_returns_content(self, tmp_path):
        """read_file() returns file content."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        ctx = Context()
        content = ctx.read_file(str(test_file))
        assert content == "test content"

    def test_read_file_raises_on_missing(self):
        """read_file() raises FileNotFoundError for missing files."""
        ctx = Context()
        with pytest.raises(FileNotFoundError):
            ctx.read_file("/nonexistent_file_xyz")
```

**Step 2: Run tests to verify they fail**

```bash
cd boxctl && python -m pytest tests/core/test_context.py -v
```

Expected: FAIL with "ModuleNotFoundError"

**Step 3: Implement Context class**

```python
# boxctl/boxctl/core/context.py
"""Execution context for testability."""

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
```

**Step 4: Update core __init__.py**

```python
# boxctl/boxctl/core/__init__.py
"""Core boxctl functionality."""

from boxctl.core.context import Context
from boxctl.core.output import Output

__all__ = ["Context", "Output"]
```

**Step 5: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/core/test_context.py -v
```

Expected: All 6 tests PASS

**Step 6: Commit**

```bash
git add boxctl/boxctl/core/context.py boxctl/tests/core/test_context.py
git commit -m "feat(core): add Context for subprocess wrapping and testability"
```

---

### Task 1.4: Implement MockContext for Testing

**Files:**
- Create: `boxctl/tests/conftest.py`
- Create: `boxctl/tests/core/test_mock_context.py`

**Step 1: Write tests for MockContext**

```python
# boxctl/tests/core/test_mock_context.py
"""Tests for MockContext test helper."""

import pytest
import subprocess


class TestMockContext:
    """Tests for MockContext fixture."""

    def test_check_tool_with_available(self, mock_context):
        """MockContext reports tools as available."""
        ctx = mock_context(tools_available=["smartctl", "lsblk"])
        assert ctx.check_tool("smartctl") is True
        assert ctx.check_tool("lsblk") is True
        assert ctx.check_tool("missing") is False

    def test_run_returns_mocked_output(self, mock_context):
        """MockContext returns configured command outputs."""
        ctx = mock_context(
            tools_available=["echo"],
            command_outputs={
                ("echo", "hello"): "hello\n",
            }
        )
        result = ctx.run(["echo", "hello"])
        assert result.stdout == "hello\n"
        assert result.returncode == 0

    def test_run_tracks_commands(self, mock_context):
        """MockContext tracks which commands were run."""
        ctx = mock_context(
            tools_available=["cmd"],
            command_outputs={
                ("cmd", "arg1"): "output1",
                ("cmd", "arg2"): "output2",
            }
        )
        ctx.run(["cmd", "arg1"])
        ctx.run(["cmd", "arg2"])
        assert ("cmd", "arg1") in [tuple(c) for c in ctx.commands_run]
        assert ("cmd", "arg2") in [tuple(c) for c in ctx.commands_run]

    def test_read_file_returns_mocked_content(self, mock_context):
        """MockContext returns configured file contents."""
        ctx = mock_context(
            file_contents={
                "/proc/mdstat": "md0 : active raid1 sda1[0] sdb1[1]",
            }
        )
        content = ctx.read_file("/proc/mdstat")
        assert "raid1" in content

    def test_read_file_raises_on_unmocked(self, mock_context):
        """MockContext raises for files not in mock."""
        ctx = mock_context()
        with pytest.raises(FileNotFoundError):
            ctx.read_file("/unmocked/path")

    def test_run_raises_on_unmocked_command(self, mock_context):
        """MockContext raises for commands not in mock."""
        ctx = mock_context(tools_available=["cmd"])
        with pytest.raises(KeyError):
            ctx.run(["cmd", "unknown_args"])
```

**Step 2: Implement conftest.py with MockContext**

```python
# boxctl/tests/conftest.py
"""Shared test fixtures."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest


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
        # For testing, return files that match pattern from file_contents
        from fnmatch import fnmatch
        return [p for p in self.file_contents.keys() if fnmatch(p, pattern)]


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
```

**Step 3: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/core/test_mock_context.py -v
```

Expected: All 6 tests PASS

**Step 4: Commit**

```bash
git add boxctl/tests/conftest.py boxctl/tests/core/test_mock_context.py
git commit -m "feat(test): add MockContext fixture for script testing"
```

---

### Task 1.5: Implement Metadata Parser

**Files:**
- Create: `boxctl/boxctl/core/metadata.py`
- Create: `boxctl/tests/core/test_metadata.py`

**Step 1: Write failing tests for metadata parsing**

```python
# boxctl/tests/core/test_metadata.py
"""Tests for script metadata parsing."""

import pytest
from boxctl.core.metadata import parse_metadata, MetadataError


VALID_HEADER = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage]
#   requires: [smartctl]
#   privilege: root
#   brief: Check disk health using SMART attributes
'''

MINIMAL_HEADER = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   brief: Minimal script
'''

NO_HEADER = '''#!/usr/bin/env python3
"""A script without boxctl metadata."""

def main():
    pass
'''

INVALID_YAML = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [unclosed
'''


class TestParseMetadata:
    """Tests for parse_metadata function."""

    def test_parses_valid_header(self):
        """Parses all fields from valid header."""
        meta = parse_metadata(VALID_HEADER)
        assert meta["category"] == "baremetal/disk"
        assert meta["tags"] == ["health", "smart", "storage"]
        assert meta["requires"] == ["smartctl"]
        assert meta["privilege"] == "root"
        assert meta["brief"] == "Check disk health using SMART attributes"

    def test_parses_minimal_header(self):
        """Parses minimal required fields."""
        meta = parse_metadata(MINIMAL_HEADER)
        assert meta["category"] == "baremetal/disk"
        assert meta["tags"] == ["health"]
        assert meta["brief"] == "Minimal script"
        assert meta.get("requires") is None
        assert meta.get("privilege") is None

    def test_returns_none_for_no_header(self):
        """Returns None for scripts without boxctl header."""
        meta = parse_metadata(NO_HEADER)
        assert meta is None

    def test_raises_on_invalid_yaml(self):
        """Raises MetadataError for malformed YAML."""
        with pytest.raises(MetadataError):
            parse_metadata(INVALID_YAML)

    def test_validates_required_fields(self):
        """Raises MetadataError when required fields missing."""
        missing_category = '''# boxctl:
#   tags: [test]
#   brief: Missing category
'''
        with pytest.raises(MetadataError, match="category"):
            parse_metadata(missing_category)

    def test_header_within_first_20_lines(self):
        """Finds header only within first 20 lines."""
        late_header = "\n" * 25 + VALID_HEADER
        meta = parse_metadata(late_header)
        assert meta is None
```

**Step 2: Run tests to verify they fail**

```bash
cd boxctl && python -m pytest tests/core/test_metadata.py -v
```

Expected: FAIL with ModuleNotFoundError

**Step 3: Implement metadata parser**

```python
# boxctl/boxctl/core/metadata.py
"""Script metadata parsing."""

import re
from typing import Any

import yaml


class MetadataError(Exception):
    """Error parsing script metadata."""
    pass


REQUIRED_FIELDS = {"category", "tags", "brief"}
HEADER_PATTERN = re.compile(r"^#\s*boxctl:\s*$", re.MULTILINE)


def parse_metadata(content: str) -> dict[str, Any] | None:
    """
    Parse boxctl metadata from script content.

    Args:
        content: Full script content as string

    Returns:
        Metadata dict or None if no header found

    Raises:
        MetadataError: If header found but invalid
    """
    # Only look in first 20 lines
    lines = content.split("\n")[:20]
    header_text = "\n".join(lines)

    # Find the boxctl: marker
    match = HEADER_PATTERN.search(header_text)
    if not match:
        return None

    # Extract YAML block (lines starting with #   after the marker)
    yaml_lines = []
    in_header = False
    for line in lines:
        if "# boxctl:" in line:
            in_header = True
            continue
        if in_header:
            if line.startswith("#   ") or line.startswith("#\t"):
                # Remove comment prefix, keep indentation
                yaml_line = line[1:].lstrip(" ").rstrip()
                if yaml_line:
                    yaml_lines.append(yaml_line)
            elif line.strip() == "#":
                continue  # Empty comment line
            else:
                break  # End of header block

    if not yaml_lines:
        return None

    yaml_content = "\n".join(yaml_lines)

    try:
        metadata = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        raise MetadataError(f"Invalid YAML in metadata: {e}")

    if not isinstance(metadata, dict):
        raise MetadataError("Metadata must be a YAML mapping")

    # Validate required fields
    missing = REQUIRED_FIELDS - set(metadata.keys())
    if missing:
        raise MetadataError(f"Missing required fields: {', '.join(missing)}")

    return metadata


def validate_metadata(metadata: dict[str, Any]) -> list[str]:
    """
    Validate metadata values.

    Returns list of warning messages (empty if valid).
    """
    warnings = []

    # Category format
    category = metadata.get("category", "")
    if not re.match(r"^(baremetal|k8s)/\w+", category):
        warnings.append(f"Invalid category format: {category}")

    # Tags is a list
    tags = metadata.get("tags", [])
    if not isinstance(tags, list) or not tags:
        warnings.append("tags must be a non-empty list")

    # Privilege values
    privilege = metadata.get("privilege")
    if privilege and privilege not in ("root", "sudo"):
        warnings.append(f"Invalid privilege value: {privilege}")

    return warnings
```

**Step 4: Update core __init__.py**

```python
# boxctl/boxctl/core/__init__.py
"""Core boxctl functionality."""

from boxctl.core.context import Context
from boxctl.core.metadata import MetadataError, parse_metadata, validate_metadata
from boxctl.core.output import Output

__all__ = [
    "Context",
    "MetadataError",
    "Output",
    "parse_metadata",
    "validate_metadata",
]
```

**Step 5: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/core/test_metadata.py -v
```

Expected: All 6 tests PASS

**Step 6: Commit**

```bash
git add boxctl/boxctl/core/metadata.py boxctl/tests/core/test_metadata.py boxctl/boxctl/core/__init__.py
git commit -m "feat(core): add metadata parser for script headers"
```

---

### Task 1.6: Implement Script Discovery

**Files:**
- Create: `boxctl/boxctl/core/discovery.py`
- Create: `boxctl/tests/core/test_discovery.py`
- Create: `boxctl/tests/fixtures/scripts/` (sample scripts for testing)

**Step 1: Create test fixture scripts**

```python
# boxctl/tests/fixtures/scripts/baremetal/disk_health.py
#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage]
#   requires: [smartctl]
#   privilege: root
#   brief: Check disk health using SMART attributes

def run(args, output, context):
    return 0
```

```python
# boxctl/tests/fixtures/scripts/baremetal/memory_monitor.py
#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, memory]
#   brief: Monitor memory usage

def run(args, output, context):
    return 0
```

```python
# boxctl/tests/fixtures/scripts/k8s/pod_status.py
#!/usr/bin/env python3
# boxctl:
#   category: k8s/pod
#   tags: [health, pod, status]
#   requires: [kubectl]
#   brief: Check pod status

def run(args, output, context):
    return 0
```

**Step 2: Write failing tests for discovery**

```python
# boxctl/tests/core/test_discovery.py
"""Tests for script discovery."""

import pytest
from pathlib import Path
from boxctl.core.discovery import (
    discover_scripts,
    filter_by_tag,
    filter_by_category,
    Script,
)


@pytest.fixture
def fixture_scripts(fixtures_dir):
    """Path to fixture scripts."""
    return fixtures_dir / "scripts"


class TestDiscoverScripts:
    """Tests for discover_scripts function."""

    def test_finds_all_scripts(self, fixture_scripts):
        """Discovers all scripts in directory."""
        scripts = discover_scripts([fixture_scripts])
        assert len(scripts) >= 3
        names = [s.name for s in scripts]
        assert "disk_health" in names
        assert "memory_monitor" in names
        assert "pod_status" in names

    def test_parses_metadata(self, fixture_scripts):
        """Parses metadata for discovered scripts."""
        scripts = discover_scripts([fixture_scripts])
        disk_health = next(s for s in scripts if s.name == "disk_health")
        assert disk_health.category == "baremetal/disk"
        assert "health" in disk_health.tags
        assert "smartctl" in disk_health.requires
        assert disk_health.privilege == "root"

    def test_respects_search_order(self, fixture_scripts, tmp_path):
        """Earlier paths take precedence (user overrides)."""
        # Create override script
        override_dir = tmp_path / "scripts" / "baremetal"
        override_dir.mkdir(parents=True)
        override_script = override_dir / "disk_health.py"
        override_script.write_text('''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [override]
#   brief: Override version
def run(args, output, context):
    return 0
''')

        # Override path first
        scripts = discover_scripts([tmp_path / "scripts", fixture_scripts])
        disk_health = next(s for s in scripts if s.name == "disk_health")
        assert "override" in disk_health.tags


class TestFilterScripts:
    """Tests for script filtering."""

    def test_filter_by_single_tag(self, fixture_scripts):
        """Filters scripts by single tag."""
        scripts = discover_scripts([fixture_scripts])
        filtered = filter_by_tag(scripts, ["health"])
        assert len(filtered) >= 3  # All have health tag

    def test_filter_by_multiple_tags_and(self, fixture_scripts):
        """Filters by multiple tags with AND logic."""
        scripts = discover_scripts([fixture_scripts])
        filtered = filter_by_tag(scripts, ["health", "smart"])
        assert len(filtered) == 1
        assert filtered[0].name == "disk_health"

    def test_filter_by_category(self, fixture_scripts):
        """Filters scripts by category."""
        scripts = discover_scripts([fixture_scripts])
        filtered = filter_by_category(scripts, "baremetal/disk")
        assert len(filtered) == 1
        assert filtered[0].name == "disk_health"

    def test_filter_by_category_prefix(self, fixture_scripts):
        """Filters by category prefix."""
        scripts = discover_scripts([fixture_scripts])
        filtered = filter_by_category(scripts, "baremetal")
        assert len(filtered) == 2
```

**Step 3: Run tests to verify they fail**

```bash
cd boxctl && python -m pytest tests/core/test_discovery.py -v
```

Expected: FAIL

**Step 4: Implement discovery module**

```python
# boxctl/boxctl/core/discovery.py
"""Script discovery and filtering."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from boxctl.core.metadata import parse_metadata, MetadataError


@dataclass
class Script:
    """Discovered script with metadata."""

    name: str
    path: Path
    category: str
    tags: list[str]
    brief: str
    requires: list[str] = field(default_factory=list)
    privilege: str | None = None
    related: list[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path) -> "Script | None":
        """Create Script from file path, or None if invalid."""
        try:
            content = path.read_text()
        except Exception:
            return None

        metadata = parse_metadata(content)
        if metadata is None:
            return None

        return cls(
            name=path.stem,
            path=path,
            category=metadata["category"],
            tags=metadata["tags"],
            brief=metadata["brief"],
            requires=metadata.get("requires", []),
            privilege=metadata.get("privilege"),
            related=metadata.get("related", []),
        )


def discover_scripts(
    search_paths: Sequence[Path],
    patterns: Sequence[str] = ("baremetal/*.py", "k8s/*.py"),
) -> list[Script]:
    """
    Discover scripts from search paths.

    Args:
        search_paths: Directories to search (earlier = higher priority)
        patterns: Glob patterns for scripts

    Returns:
        List of Script objects (no duplicates, first match wins)
    """
    seen_names: set[str] = set()
    scripts: list[Script] = []

    for search_path in search_paths:
        if not search_path.exists():
            continue

        for pattern in patterns:
            for path in search_path.glob(pattern):
                if not path.is_file():
                    continue

                name = path.stem
                if name in seen_names:
                    continue  # Skip duplicates (earlier path wins)

                script = Script.from_file(path)
                if script:
                    scripts.append(script)
                    seen_names.add(name)

    return scripts


def filter_by_tag(scripts: list[Script], tags: list[str]) -> list[Script]:
    """
    Filter scripts by tags (AND logic).

    All specified tags must be present on script.
    """
    return [s for s in scripts if all(t in s.tags for t in tags)]


def filter_by_category(scripts: list[Script], category: str) -> list[Script]:
    """
    Filter scripts by category or category prefix.

    "baremetal" matches "baremetal/disk", "baremetal/memory", etc.
    "baremetal/disk" matches only "baremetal/disk".
    """
    return [
        s for s in scripts
        if s.category == category or s.category.startswith(f"{category}/")
    ]


def search_scripts(scripts: list[Script], query: str) -> list[Script]:
    """
    Search scripts by query string.

    Matches against name, brief, and tags.
    """
    query = query.lower()
    return [
        s for s in scripts
        if query in s.name.lower()
        or query in s.brief.lower()
        or any(query in t.lower() for t in s.tags)
    ]
```

**Step 5: Create fixture directories**

```bash
mkdir -p boxctl/tests/fixtures/scripts/baremetal
mkdir -p boxctl/tests/fixtures/scripts/k8s
```

Then create the fixture script files from Step 1.

**Step 6: Update core __init__.py**

```python
# boxctl/boxctl/core/__init__.py
"""Core boxctl functionality."""

from boxctl.core.context import Context
from boxctl.core.discovery import (
    Script,
    discover_scripts,
    filter_by_category,
    filter_by_tag,
    search_scripts,
)
from boxctl.core.metadata import MetadataError, parse_metadata, validate_metadata
from boxctl.core.output import Output

__all__ = [
    "Context",
    "MetadataError",
    "Output",
    "Script",
    "discover_scripts",
    "filter_by_category",
    "filter_by_tag",
    "parse_metadata",
    "search_scripts",
    "validate_metadata",
]
```

**Step 7: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/core/test_discovery.py -v
```

Expected: All tests PASS

**Step 8: Commit**

```bash
git add boxctl/boxctl/core/discovery.py boxctl/tests/core/test_discovery.py boxctl/tests/fixtures/scripts/
git commit -m "feat(core): add script discovery and filtering"
```

---

### Task 1.7: Implement Script Runner

**Files:**
- Create: `boxctl/boxctl/core/runner.py`
- Create: `boxctl/tests/core/test_runner.py`

**Step 1: Write failing tests for runner**

```python
# boxctl/tests/core/test_runner.py
"""Tests for script runner."""

import pytest
from pathlib import Path
from boxctl.core.runner import run_script, RunResult
from boxctl.core.discovery import Script


@pytest.fixture
def simple_script(tmp_path):
    """Create a simple test script."""
    script_path = tmp_path / "test_script.py"
    script_path.write_text('''#!/usr/bin/env python3
# boxctl:
#   category: test/simple
#   tags: [test]
#   brief: Test script

def run(args, output, context):
    output.emit({"status": "ok", "args": args})
    return 0
''')
    return Script(
        name="test_script",
        path=script_path,
        category="test/simple",
        tags=["test"],
        brief="Test script",
    )


@pytest.fixture
def failing_script(tmp_path):
    """Create a script that returns warning."""
    script_path = tmp_path / "failing_script.py"
    script_path.write_text('''#!/usr/bin/env python3
# boxctl:
#   category: test/fail
#   tags: [test]
#   brief: Failing script

def run(args, output, context):
    output.warning("Something is wrong")
    return 1
''')
    return Script(
        name="failing_script",
        path=script_path,
        category="test/fail",
        tags=["test"],
        brief="Failing script",
    )


class TestRunScript:
    """Tests for run_script function."""

    def test_runs_simple_script(self, simple_script, mock_context):
        """Runs script and captures output."""
        ctx = mock_context(tools_available=[])
        result = run_script(simple_script, [], ctx)

        assert result.exit_code == 0
        assert result.output.data["status"] == "ok"

    def test_passes_args_to_script(self, simple_script, mock_context):
        """Passes command-line args to script."""
        ctx = mock_context(tools_available=[])
        result = run_script(simple_script, ["--verbose", "--format=json"], ctx)

        assert "--verbose" in result.output.data["args"]
        assert "--format=json" in result.output.data["args"]

    def test_captures_warnings(self, failing_script, mock_context):
        """Captures warning from script."""
        ctx = mock_context(tools_available=[])
        result = run_script(failing_script, [], ctx)

        assert result.exit_code == 1
        assert "Something is wrong" in result.output.warnings

    def test_records_duration(self, simple_script, mock_context):
        """Records script execution duration."""
        ctx = mock_context(tools_available=[])
        result = run_script(simple_script, [], ctx)

        assert result.duration_ms >= 0

    def test_handles_missing_run_function(self, tmp_path, mock_context):
        """Handles scripts without run function."""
        script_path = tmp_path / "bad_script.py"
        script_path.write_text('''#!/usr/bin/env python3
# boxctl:
#   category: test/bad
#   tags: [test]
#   brief: Bad script
# No run function!
''')
        script = Script(
            name="bad_script",
            path=script_path,
            category="test/bad",
            tags=["test"],
            brief="Bad script",
        )
        ctx = mock_context(tools_available=[])
        result = run_script(script, [], ctx)

        assert result.exit_code == 2
        assert result.output.errors
```

**Step 2: Run tests to verify they fail**

```bash
cd boxctl && python -m pytest tests/core/test_runner.py -v
```

Expected: FAIL

**Step 3: Implement runner module**

```python
# boxctl/boxctl/core/runner.py
"""Script execution."""

import importlib.util
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxctl.core.context import Context
from boxctl.core.discovery import Script
from boxctl.core.output import Output


@dataclass
class RunResult:
    """Result of running a script."""

    script: Script
    exit_code: int
    output: Output
    duration_ms: int
    error: str | None = None


def load_script_module(script: Script) -> Any:
    """
    Dynamically load a script as a module.

    Returns the module object.
    """
    spec = importlib.util.spec_from_file_location(
        f"boxctl.scripts.{script.name}",
        script.path,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load script: {script.path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_script(
    script: Script,
    args: list[str],
    context: Context | None = None,
) -> RunResult:
    """
    Execute a script.

    Args:
        script: Script to run
        args: Arguments to pass to script
        context: Execution context (uses real Context if None)

    Returns:
        RunResult with exit code, output, and timing
    """
    if context is None:
        context = Context()

    output = Output()
    start_time = time.monotonic()

    try:
        module = load_script_module(script)

        if not hasattr(module, "run"):
            output.error(f"Script {script.name} has no run() function")
            return RunResult(
                script=script,
                exit_code=2,
                output=output,
                duration_ms=0,
                error="Missing run() function",
            )

        exit_code = module.run(args, output, context)

        if not isinstance(exit_code, int):
            exit_code = 0

    except Exception as e:
        output.error(f"Script error: {e}")
        exit_code = 2
        error = str(e)
    else:
        error = None

    duration_ms = int((time.monotonic() - start_time) * 1000)

    return RunResult(
        script=script,
        exit_code=exit_code,
        output=output,
        duration_ms=duration_ms,
        error=error,
    )


def check_requirements(script: Script, context: Context) -> list[str]:
    """
    Check if script requirements are met.

    Returns list of missing requirements.
    """
    missing = []
    for tool in script.requires:
        if not context.check_tool(tool):
            missing.append(tool)
    return missing
```

**Step 4: Update core __init__.py**

```python
# boxctl/boxctl/core/__init__.py
"""Core boxctl functionality."""

from boxctl.core.context import Context
from boxctl.core.discovery import (
    Script,
    discover_scripts,
    filter_by_category,
    filter_by_tag,
    search_scripts,
)
from boxctl.core.metadata import MetadataError, parse_metadata, validate_metadata
from boxctl.core.output import Output
from boxctl.core.runner import RunResult, check_requirements, run_script

__all__ = [
    "Context",
    "MetadataError",
    "Output",
    "RunResult",
    "Script",
    "check_requirements",
    "discover_scripts",
    "filter_by_category",
    "filter_by_tag",
    "parse_metadata",
    "run_script",
    "search_scripts",
    "validate_metadata",
]
```

**Step 5: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/core/test_runner.py -v
```

Expected: All tests PASS

**Step 6: Commit**

```bash
git add boxctl/boxctl/core/runner.py boxctl/tests/core/test_runner.py boxctl/boxctl/core/__init__.py
git commit -m "feat(core): add script runner with dynamic loading"
```

---

### Task 1.8: Implement Privilege Escalation

**Files:**
- Modify: `boxctl/boxctl/core/runner.py`
- Create: `boxctl/tests/core/test_privilege.py`

**Step 1: Write failing tests for privilege handling**

```python
# boxctl/tests/core/test_privilege.py
"""Tests for privilege escalation."""

import os
import pytest
from unittest.mock import patch, MagicMock
from boxctl.core.runner import run_script, needs_privilege_escalation
from boxctl.core.discovery import Script


@pytest.fixture
def root_script(tmp_path):
    """Create a script requiring root."""
    script_path = tmp_path / "root_script.py"
    script_path.write_text('''#!/usr/bin/env python3
# boxctl:
#   category: test/priv
#   tags: [test]
#   privilege: root
#   brief: Needs root

def run(args, output, context):
    output.emit({"ran_as": "test"})
    return 0
''')
    return Script(
        name="root_script",
        path=script_path,
        category="test/priv",
        tags=["test"],
        brief="Needs root",
        privilege="root",
    )


class TestPrivilegeEscalation:
    """Tests for privilege handling."""

    def test_needs_escalation_when_not_root(self, root_script):
        """Detects need for escalation when not root."""
        with patch('os.geteuid', return_value=1000):
            assert needs_privilege_escalation(root_script) is True

    def test_no_escalation_when_root(self, root_script):
        """No escalation needed when running as root."""
        with patch('os.geteuid', return_value=0):
            assert needs_privilege_escalation(root_script) is False

    def test_no_escalation_for_unprivileged_script(self, tmp_path):
        """No escalation for scripts without privilege requirement."""
        script = Script(
            name="normal",
            path=tmp_path / "normal.py",
            category="test/normal",
            tags=["test"],
            brief="Normal script",
            privilege=None,
        )
        assert needs_privilege_escalation(script) is False

    def test_sudo_escalation_invokes_sudo(self, root_script, mock_context):
        """Running privileged script invokes sudo."""
        ctx = mock_context(tools_available=["sudo"])

        with patch('os.geteuid', return_value=1000):
            with patch('boxctl.core.runner.run_with_sudo') as mock_sudo:
                mock_sudo.return_value = MagicMock(exit_code=0)
                result = run_script(root_script, [], ctx, escalate=True)
                mock_sudo.assert_called_once()

    def test_fails_when_sudo_unavailable(self, root_script, mock_context):
        """Fails gracefully when sudo not available."""
        ctx = mock_context(tools_available=[])

        with patch('os.geteuid', return_value=1000):
            result = run_script(root_script, [], ctx, escalate=True)
            assert result.exit_code == 2
            assert "sudo" in result.output.errors[0].lower() or "privilege" in result.output.errors[0].lower()
```

**Step 2: Run tests to verify they fail**

```bash
cd boxctl && python -m pytest tests/core/test_privilege.py -v
```

Expected: FAIL

**Step 3: Update runner with privilege escalation**

Add to `boxctl/boxctl/core/runner.py`:

```python
import os
import shutil

def needs_privilege_escalation(script: Script) -> bool:
    """Check if script needs privilege escalation."""
    if script.privilege not in ("root", "sudo"):
        return False
    return os.geteuid() != 0


def run_with_sudo(
    script: Script,
    args: list[str],
    context: Context,
) -> RunResult:
    """
    Run script with sudo.

    Invokes the script via sudo using the bundled Python.
    """
    output = Output()
    start_time = time.monotonic()

    # Find our Python interpreter
    python_path = sys.executable
    boxctl_home = os.environ.get("BOXCTL_HOME", "")

    # Build sudo command
    cmd = ["sudo", python_path, str(script.path)] + args

    try:
        result = context.run(cmd, timeout=300)
        # Parse output if JSON
        try:
            import json
            data = json.loads(result.stdout)
            output.emit(data)
            exit_code = 0
        except (json.JSONDecodeError, ValueError):
            output.emit({"raw_output": result.stdout})
            exit_code = result.returncode
    except Exception as e:
        output.error(f"Sudo execution failed: {e}")
        exit_code = 2

    duration_ms = int((time.monotonic() - start_time) * 1000)

    return RunResult(
        script=script,
        exit_code=exit_code,
        output=output,
        duration_ms=duration_ms,
    )


def run_script(
    script: Script,
    args: list[str],
    context: Context | None = None,
    escalate: bool = True,
    timeout: int = 60,
) -> RunResult:
    """
    Execute a script.

    Args:
        script: Script to run
        args: Arguments to pass to script
        context: Execution context (uses real Context if None)
        escalate: Whether to use sudo if needed
        timeout: Script timeout in seconds

    Returns:
        RunResult with exit code, output, and timing
    """
    if context is None:
        context = Context()

    # Check privilege requirements
    if escalate and needs_privilege_escalation(script):
        if not context.check_tool("sudo"):
            output = Output()
            output.error(f"Script {script.name} requires root privileges but sudo is not available")
            return RunResult(
                script=script,
                exit_code=2,
                output=output,
                duration_ms=0,
                error="Sudo not available",
            )
        return run_with_sudo(script, args, context)

    # Normal execution (rest of existing run_script code)
    # ... existing implementation ...
```

**Step 4: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/core/test_privilege.py -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add boxctl/boxctl/core/runner.py boxctl/tests/core/test_privilege.py
git commit -m "feat(core): add privilege escalation with sudo support"
```

---

### Task 1.9: Implement Shared Utilities Package

**Files:**
- Create: `boxctl/boxctl/lib/__init__.py`
- Create: `boxctl/boxctl/lib/process.py`
- Create: `boxctl/boxctl/lib/filesystem.py`
- Create: `boxctl/boxctl/lib/network.py`
- Create: `boxctl/tests/lib/test_process.py`

**Step 1: Create lib package structure**

```bash
mkdir -p boxctl/boxctl/lib
mkdir -p boxctl/tests/lib
touch boxctl/boxctl/lib/__init__.py
touch boxctl/tests/lib/__init__.py
```

**Step 2: Write tests for process utilities**

```python
# boxctl/tests/lib/test_process.py
"""Tests for process utilities."""

import pytest
from boxctl.lib.process import (
    parse_ps_output,
    get_process_by_name,
    get_process_tree,
)


class TestProcessUtils:
    """Tests for process utilities."""

    def test_parse_ps_output(self, mock_context):
        """Parses ps aux output correctly."""
        ps_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0 169456 13100 ?        Ss   Jan01   1:23 /sbin/init
root       123  0.5  1.2 456789 12345 ?        Sl   10:00   0:05 /usr/bin/dockerd
"""
        ctx = mock_context(
            tools_available=["ps"],
            command_outputs={("ps", "aux"): ps_output}
        )

        procs = parse_ps_output(ctx)

        assert len(procs) == 2
        assert procs[0]["pid"] == 1
        assert procs[0]["command"] == "/sbin/init"
        assert procs[1]["pid"] == 123

    def test_get_process_by_name(self, mock_context):
        """Finds processes by name."""
        ps_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root       123  0.5  1.2 456789 12345 ?        Sl   10:00   0:05 /usr/bin/dockerd
root       456  0.1  0.5 123456 54321 ?        Ss   10:01   0:01 /usr/bin/containerd
"""
        ctx = mock_context(
            tools_available=["ps"],
            command_outputs={("ps", "aux"): ps_output}
        )

        result = get_process_by_name("dockerd", ctx)

        assert len(result) == 1
        assert result[0]["pid"] == 123
```

**Step 3: Implement process utilities**

```python
# boxctl/boxctl/lib/process.py
"""Process-related utilities for scripts."""

import re
from typing import Any

from boxctl.core.context import Context


def parse_ps_output(context: Context) -> list[dict[str, Any]]:
    """
    Parse ps aux output into structured data.

    Returns list of process dicts with pid, user, cpu, mem, command.
    """
    result = context.run(["ps", "aux"])
    lines = result.stdout.strip().split("\n")

    if len(lines) < 2:
        return []

    processes = []
    for line in lines[1:]:  # Skip header
        parts = line.split(None, 10)  # Split into max 11 parts
        if len(parts) >= 11:
            processes.append({
                "user": parts[0],
                "pid": int(parts[1]),
                "cpu": float(parts[2]),
                "mem": float(parts[3]),
                "vsz": int(parts[4]),
                "rss": int(parts[5]),
                "tty": parts[6],
                "stat": parts[7],
                "start": parts[8],
                "time": parts[9],
                "command": parts[10],
            })

    return processes


def get_process_by_name(name: str, context: Context) -> list[dict[str, Any]]:
    """Find processes matching a name."""
    procs = parse_ps_output(context)
    return [p for p in procs if name in p["command"]]


def get_process_tree(pid: int, context: Context) -> dict[str, Any]:
    """Get process tree starting from pid."""
    result = context.run(["pstree", "-p", str(pid)], check=False)
    return {"pid": pid, "tree": result.stdout}
```

**Step 4: Implement filesystem utilities**

```python
# boxctl/boxctl/lib/filesystem.py
"""Filesystem utilities for scripts."""

import re
from typing import Any

from boxctl.core.context import Context


def parse_df_output(context: Context) -> list[dict[str, Any]]:
    """Parse df -h output into structured data."""
    result = context.run(["df", "-h"])
    lines = result.stdout.strip().split("\n")

    if len(lines) < 2:
        return []

    filesystems = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            # Parse percentage
            use_pct = int(parts[4].rstrip("%")) if parts[4].endswith("%") else 0
            filesystems.append({
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "use_percent": use_pct,
                "mountpoint": parts[5],
            })

    return filesystems


def get_mount_options(mountpoint: str, context: Context) -> dict[str, Any]:
    """Get mount options for a mountpoint."""
    content = context.read_file("/proc/mounts")
    for line in content.split("\n"):
        parts = line.split()
        if len(parts) >= 4 and parts[1] == mountpoint:
            return {
                "device": parts[0],
                "mountpoint": parts[1],
                "fstype": parts[2],
                "options": parts[3].split(","),
            }
    return {}


def parse_lsblk_output(context: Context) -> list[dict[str, Any]]:
    """Parse lsblk output into structured data."""
    result = context.run(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT", "-J"])
    import json
    data = json.loads(result.stdout)
    return data.get("blockdevices", [])
```

**Step 5: Create lib __init__.py**

```python
# boxctl/boxctl/lib/__init__.py
"""Shared utilities for boxctl scripts."""

from boxctl.lib.process import (
    parse_ps_output,
    get_process_by_name,
    get_process_tree,
)
from boxctl.lib.filesystem import (
    parse_df_output,
    get_mount_options,
    parse_lsblk_output,
)

__all__ = [
    "parse_ps_output",
    "get_process_by_name",
    "get_process_tree",
    "parse_df_output",
    "get_mount_options",
    "parse_lsblk_output",
]
```

**Step 6: Run tests**

```bash
cd boxctl && python -m pytest tests/lib/ -v
```

Expected: All tests PASS

**Step 7: Commit**

```bash
git add boxctl/boxctl/lib/ boxctl/tests/lib/
git commit -m "feat(lib): add shared utilities for process and filesystem operations"
```

---

### Task 1.10: Implement Basic CLI

**Files:**
- Create: `boxctl/boxctl/cli.py`
- Create: `boxctl/tests/test_cli.py`

**Step 1: Write failing tests for CLI**

```python
# boxctl/tests/test_cli.py
"""Tests for CLI interface."""

import subprocess
import sys
import pytest


def run_boxctl(*args):
    """Run boxctl CLI and return result."""
    result = subprocess.run(
        [sys.executable, "-m", "boxctl", *args],
        capture_output=True,
        text=True,
        cwd="boxctl",
    )
    return result


class TestCLI:
    """Tests for CLI commands."""

    def test_version(self):
        """--version shows version info."""
        result = run_boxctl("--version")
        assert result.returncode == 0
        assert "0.1.0" in result.stdout

    def test_help(self):
        """--help shows usage."""
        result = run_boxctl("--help")
        assert result.returncode == 0
        assert "boxctl" in result.stdout
        assert "list" in result.stdout
        assert "run" in result.stdout

    def test_list_help(self):
        """list --help shows list usage."""
        result = run_boxctl("list", "--help")
        assert result.returncode == 0
        assert "--tag" in result.stdout
        assert "--category" in result.stdout

    def test_run_help(self):
        """run --help shows run usage."""
        result = run_boxctl("run", "--help")
        assert result.returncode == 0
        assert "script" in result.stdout.lower()

    def test_unknown_command(self):
        """Unknown command shows error."""
        result = run_boxctl("unknown_command")
        assert result.returncode != 0
```

**Step 2: Run tests to verify they fail**

```bash
cd boxctl && python -m pytest tests/test_cli.py -v
```

Expected: FAIL

**Step 3: Implement CLI**

```python
# boxctl/boxctl/cli.py
"""Command-line interface for boxctl."""

import argparse
import sys
from pathlib import Path

from boxctl import __version__
from boxctl.core import (
    Context,
    discover_scripts,
    filter_by_category,
    filter_by_tag,
    run_script,
    search_scripts,
    check_requirements,
)


def get_script_paths() -> list[Path]:
    """Get script search paths in priority order."""
    paths = []

    # User overrides first
    user_scripts = Path.home() / ".config" / "boxctl" / "scripts"
    if user_scripts.exists():
        paths.append(user_scripts)

    # Bundled scripts (relative to this file in installed location)
    # For development, check parent directories
    boxctl_home = Path(__file__).parent.parent
    bundled = boxctl_home / "scripts"
    if bundled.exists():
        paths.append(bundled)

    # Fallback: current directory scripts
    local = Path.cwd() / "scripts"
    if local.exists():
        paths.append(local)

    return paths


def cmd_list(args):
    """List available scripts."""
    paths = get_script_paths()
    scripts = discover_scripts(paths)

    if args.tag:
        scripts = filter_by_tag(scripts, args.tag)
    if args.category:
        scripts = filter_by_category(scripts, args.category)

    if not scripts:
        print("No scripts found.")
        return 0

    # Group by category
    by_category: dict[str, list] = {}
    for s in scripts:
        cat = s.category.split("/")[0]
        by_category.setdefault(cat, []).append(s)

    for category in sorted(by_category.keys()):
        print(f"\n{category}:")
        for s in sorted(by_category[category], key=lambda x: x.name):
            tags = ", ".join(s.tags[:3])
            print(f"  {s.name:40} {s.brief[:50]}")

    print(f"\nTotal: {len(scripts)} scripts")
    return 0


def cmd_run(args):
    """Run a script or scripts matching filters."""
    paths = get_script_paths()
    scripts = discover_scripts(paths)

    # Find script(s) to run
    to_run = []
    if args.script:
        matching = [s for s in scripts if s.name == args.script]
        if not matching:
            print(f"Error: Script '{args.script}' not found", file=sys.stderr)
            return 2
        to_run = matching
    elif args.tag:
        to_run = filter_by_tag(scripts, args.tag)
    elif args.category:
        to_run = filter_by_category(scripts, args.category)
    else:
        print("Error: Specify script name, --tag, or --category", file=sys.stderr)
        return 2

    if not to_run:
        print("No scripts match the criteria.", file=sys.stderr)
        return 2

    if args.dry_run:
        print("Would run:")
        for s in to_run:
            print(f"  {s.name}")
        return 0

    # Run scripts
    context = Context()
    failed = 0
    skipped = 0

    for script in to_run:
        # Check requirements
        missing = check_requirements(script, context)
        if missing and not args.best_effort:
            print(f"Error: {script.name} requires: {', '.join(missing)}", file=sys.stderr)
            return 2
        elif missing:
            print(f"Skipping {script.name} (missing: {', '.join(missing)})")
            skipped += 1
            continue

        # Run
        print(f"Running {script.name}...")
        result = run_script(script, args.script_args or [], context)

        # Show result
        if result.exit_code == 0:
            print(f"  OK ({result.duration_ms}ms)")
        elif result.exit_code == 1:
            print(f"  WARNING: {result.output.summary} ({result.duration_ms}ms)")
            failed += 1
        else:
            print(f"  ERROR: {result.output.summary} ({result.duration_ms}ms)")
            failed += 1

    # Summary
    total = len(to_run)
    ok = total - failed - skipped
    print(f"\nSummary: {ok} ok, {failed} warnings/errors, {skipped} skipped")

    return 1 if failed > 0 else 0


def cmd_show(args):
    """Show details about a script."""
    paths = get_script_paths()
    scripts = discover_scripts(paths)

    matching = [s for s in scripts if s.name == args.script]
    if not matching:
        print(f"Error: Script '{args.script}' not found", file=sys.stderr)
        return 2

    script = matching[0]
    print(f"Name:     {script.name}")
    print(f"Category: {script.category}")
    print(f"Tags:     {', '.join(script.tags)}")
    print(f"Brief:    {script.brief}")
    print(f"Path:     {script.path}")
    if script.requires:
        print(f"Requires: {', '.join(script.requires)}")
    if script.privilege:
        print(f"Privilege: {script.privilege}")
    if script.related:
        print(f"Related:  {', '.join(script.related)}")

    return 0


def cmd_search(args):
    """Search for scripts."""
    paths = get_script_paths()
    scripts = discover_scripts(paths)

    results = search_scripts(scripts, args.query)

    if not results:
        print(f"No scripts matching '{args.query}'")
        return 0

    for s in results:
        print(f"{s.name:40} {s.brief[:50]}")

    return 0


def main(argv=None):
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="boxctl",
        description="Unified CLI for baremetal and Kubernetes utility scripts",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"boxctl {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # list command
    list_parser = subparsers.add_parser("list", help="List available scripts")
    list_parser.add_argument("--tag", action="append", help="Filter by tag (AND logic)")
    list_parser.add_argument("--category", help="Filter by category")

    # run command
    run_parser = subparsers.add_parser("run", help="Run a script")
    run_parser.add_argument("script", nargs="?", help="Script name to run")
    run_parser.add_argument("--tag", action="append", help="Run scripts with tag")
    run_parser.add_argument("--category", help="Run scripts in category")
    run_parser.add_argument("--dry-run", action="store_true", help="Show what would run")
    run_parser.add_argument("--best-effort", action="store_true", help="Skip scripts with missing deps")
    run_parser.add_argument("script_args", nargs="*", help="Arguments to pass to script")

    # show command
    show_parser = subparsers.add_parser("show", help="Show script details")
    show_parser.add_argument("script", help="Script name")

    # search command
    search_parser = subparsers.add_parser("search", help="Search for scripts")
    search_parser.add_argument("query", help="Search query")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "list": cmd_list,
        "run": cmd_run,
        "show": cmd_show,
        "search": cmd_search,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
```

**Step 4: Run tests to verify they pass**

```bash
cd boxctl && python -m pytest tests/test_cli.py -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add boxctl/boxctl/cli.py boxctl/tests/test_cli.py
git commit -m "feat(cli): add basic CLI with list, run, show, search commands"
```

---

## Phase 2: Build Pipeline

### Task 2.1: Create Build Script for python-build-standalone

**Files:**
- Create: `boxctl/scripts/build.sh`
- Create: `boxctl/scripts/setup-dev.sh`

**Step 1: Create development setup script**

```bash
#!/bin/bash
# boxctl/scripts/setup-dev.sh
# Set up development environment

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Setting up boxctl development environment..."

# Create virtual environment if needed
if [ ! -d "$PROJECT_DIR/.venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$PROJECT_DIR/.venv"
fi

# Activate and install
source "$PROJECT_DIR/.venv/bin/activate"
pip install -e ".[dev]"

echo "Development environment ready!"
echo "Activate with: source .venv/bin/activate"
```

**Step 2: Create build script**

```bash
#!/bin/bash
# boxctl/scripts/build.sh
# Build boxctl distribution with bundled Python runtime

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
DIST_DIR="$PROJECT_DIR/dist"

# Configuration
PYTHON_VERSION="${PYTHON_VERSION:-3.11.7}"
PYTHON_BUILD_DATE="${PYTHON_BUILD_DATE:-20240107}"
ARCH="${ARCH:-x86_64}"
PLATFORM="${PLATFORM:-unknown-linux-gnu}"

PYTHON_URL="https://github.com/indygreg/python-build-standalone/releases/download/${PYTHON_BUILD_DATE}/cpython-${PYTHON_VERSION}+${PYTHON_BUILD_DATE}-${ARCH}-${PLATFORM}-install_only.tar.gz"

# SHA256 checksums for verification (update when changing versions)
declare -A PYTHON_CHECKSUMS=(
    ["3.11.7-x86_64"]="a]d9e50ef9f6a11168816b5b0a67dc0c7c6e8f4a2c5b3e0c7d9f1a2b3c4d5e6f7a"
)

echo "Building boxctl distribution..."
echo "Python: ${PYTHON_VERSION}"
echo "Platform: ${ARCH}-${PLATFORM}"

# Clean previous builds
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

# Download Python runtime
echo "Downloading Python runtime..."
PYTHON_TARBALL="$BUILD_DIR/python.tar.gz"
if [ ! -f "$PYTHON_TARBALL" ]; then
    curl -L "$PYTHON_URL" -o "$PYTHON_TARBALL"
fi

# Verify checksum
CHECKSUM_KEY="${PYTHON_VERSION}-${ARCH}"
if [[ -n "${PYTHON_CHECKSUMS[$CHECKSUM_KEY]:-}" ]]; then
    echo "Verifying checksum..."
    EXPECTED="${PYTHON_CHECKSUMS[$CHECKSUM_KEY]}"
    ACTUAL=$(sha256sum "$PYTHON_TARBALL" | cut -d' ' -f1)
    if [[ "$ACTUAL" != "$EXPECTED" ]]; then
        echo "ERROR: Checksum mismatch!"
        echo "Expected: $EXPECTED"
        echo "Actual:   $ACTUAL"
        exit 1
    fi
    echo "Checksum verified."
else
    echo "WARNING: No checksum available for $CHECKSUM_KEY"
fi

# Extract runtime
echo "Extracting Python runtime..."
mkdir -p "$BUILD_DIR/runtime"
tar xzf "$PYTHON_TARBALL" -C "$BUILD_DIR/runtime" --strip-components=1

# Install dependencies into runtime
echo "Installing dependencies..."
"$BUILD_DIR/runtime/bin/pip" install pyyaml

# Install boxctl core
echo "Installing boxctl..."
"$BUILD_DIR/runtime/bin/pip" install "$PROJECT_DIR"

# Copy scripts
echo "Copying scripts..."
mkdir -p "$BUILD_DIR/scripts"
if [ -d "$PROJECT_DIR/scripts/baremetal" ]; then
    cp -r "$PROJECT_DIR/scripts/baremetal" "$BUILD_DIR/scripts/"
fi
if [ -d "$PROJECT_DIR/scripts/k8s" ]; then
    cp -r "$PROJECT_DIR/scripts/k8s" "$BUILD_DIR/scripts/"
fi

# Copy profiles
echo "Copying profiles..."
mkdir -p "$BUILD_DIR/profiles"
if [ -d "$PROJECT_DIR/profiles" ]; then
    cp -r "$PROJECT_DIR/profiles/"* "$BUILD_DIR/profiles/" 2>/dev/null || true
fi

# Create wrapper script
echo "Creating wrapper..."
mkdir -p "$BUILD_DIR/bin"
cat > "$BUILD_DIR/bin/boxctl" << 'EOF'
#!/bin/bash
set -euo pipefail
BOXCTL_HOME="${BOXCTL_HOME:-$(dirname "$(dirname "$(readlink -f "$0")")")}"
export BOXCTL_HOME
exec "$BOXCTL_HOME/runtime/bin/python3" -m boxctl "$@"
EOF
chmod +x "$BUILD_DIR/bin/boxctl"

# Create version file
echo "Creating version info..."
VERSION=$(grep -Po '(?<=version = ")[^"]+' "$PROJECT_DIR/pyproject.toml")
cat > "$BUILD_DIR/VERSION" << EOF
boxctl ${VERSION}
Python: ${PYTHON_VERSION}
Platform: ${ARCH}-${PLATFORM}
Built: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Package
echo "Creating distribution archive..."
ARCHIVE_NAME="boxctl-${VERSION}-linux-${ARCH}.tar.gz"
tar czf "$DIST_DIR/$ARCHIVE_NAME" -C "$BUILD_DIR" .

# Create scripts-only archive
echo "Creating scripts-only archive..."
tar czf "$DIST_DIR/boxctl-scripts-${VERSION}.tar.gz" -C "$BUILD_DIR" scripts profiles

echo ""
echo "Build complete!"
echo "Distribution: $DIST_DIR/$ARCHIVE_NAME"
ls -lh "$DIST_DIR/"
```

**Step 3: Make scripts executable**

```bash
chmod +x boxctl/scripts/build.sh boxctl/scripts/setup-dev.sh
```

**Step 4: Commit**

```bash
git add boxctl/scripts/
git commit -m "feat(build): add build scripts for python-build-standalone distribution"
```

---

### Task 2.2: Create Makefile

**Files:**
- Create: `boxctl/Makefile`

**Step 1: Create Makefile**

```makefile
# boxctl/Makefile
.PHONY: all setup test test-cov lint build clean install

PYTHON := python3
PYTEST := pytest
VERSION := $(shell grep -Po '(?<=version = ")[^"]+' pyproject.toml)

all: test

setup:
	./scripts/setup-dev.sh

test:
	$(PYTEST) tests/ -v --ignore=tests/integration

test-cov:
	$(PYTEST) tests/ -v --ignore=tests/integration \
		--cov=boxctl --cov-report=term-missing --cov-fail-under=80

test-integration:
	$(PYTEST) tests/integration/ -v

test-all: test test-integration

lint:
	$(PYTHON) -m boxctl lint --all

build:
	./scripts/build.sh

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

install: build
	sudo tar xzf dist/boxctl-$(VERSION)-linux-*.tar.gz -C /opt/boxctl
	sudo ln -sf /opt/boxctl/bin/boxctl /usr/local/bin/boxctl
```

**Step 2: Commit**

```bash
git add boxctl/Makefile
git commit -m "feat(build): add Makefile for common tasks"
```

---

## Phase 3: Migrate First Script (disk_health)

This phase establishes the pattern for migrating all ~200 scripts.

### Task 3.1: Create Fixture for smartctl Output

**Files:**
- Create: `boxctl/tests/fixtures/smartctl/healthy_ssd.txt`
- Create: `boxctl/tests/fixtures/smartctl/failing_hdd.txt`

**Step 1: Create healthy SSD fixture**

```
# boxctl/tests/fixtures/smartctl/healthy_ssd.txt
smartctl 7.2 2020-12-30 r5155 [x86_64-linux-5.15.0] (local build)
Copyright (C) 2002-20, Bruce Allen, Christian Franke, www.smartmontools.org

=== START OF INFORMATION SECTION ===
Model Family:     Samsung SSD 860
Device Model:     Samsung SSD 860 EVO 500GB
Serial Number:    S3YANB0K123456P
Firmware Version: RVT02B6Q
User Capacity:    500,107,862,016 bytes [500 GB]
Sector Size:      512 bytes logical/physical
Rotation Rate:    Solid State Device
SMART support is: Available - device has SMART capability.
SMART support is: Enabled

=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED
```

**Step 2: Create failing HDD fixture**

```
# boxctl/tests/fixtures/smartctl/failing_hdd.txt
smartctl 7.2 2020-12-30 r5155 [x86_64-linux-5.15.0] (local build)
Copyright (C) 2002-20, Bruce Allen, Christian Franke, www.smartmontools.org

=== START OF INFORMATION SECTION ===
Model Family:     Seagate Barracuda 2.5 5400
Device Model:     ST1000LM048-2E7172
Serial Number:    WCT12345
Firmware Version: 0001
User Capacity:    1,000,204,886,016 bytes [1.00 TB]
Sector Sizes:     512 bytes logical, 4096 bytes physical
Rotation Rate:    5400 rpm
SMART support is: Available - device has SMART capability.
SMART support is: Enabled

=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: FAILED!
Drive failure expected in less than 24 hours. SAVE ALL DATA.

SMART Attributes Data Structure revision number: 10
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   036   036   036    Pre-fail  Always   FAILING_NOW 327
```

**Step 3: Commit fixtures**

```bash
mkdir -p boxctl/tests/fixtures/smartctl
git add boxctl/tests/fixtures/smartctl/
git commit -m "test(fixtures): add smartctl output fixtures"
```

---

### Task 3.2: Migrate disk_health Script

**Files:**
- Create: `boxctl/scripts/baremetal/disk_health.py`
- Create: `boxctl/tests/scripts/baremetal/test_disk_health.py`

**Step 1: Write failing tests**

```python
# boxctl/tests/scripts/baremetal/test_disk_health.py
"""Tests for disk_health script."""

import pytest
from pathlib import Path

# Will be imported after script is created
# from boxctl.scripts.baremetal import disk_health
from boxctl.core.output import Output


@pytest.fixture
def smartctl_healthy(fixtures_dir):
    """Load healthy SSD smartctl output."""
    return (fixtures_dir / "smartctl" / "healthy_ssd.txt").read_text()


@pytest.fixture
def smartctl_failing(fixtures_dir):
    """Load failing HDD smartctl output."""
    return (fixtures_dir / "smartctl" / "failing_hdd.txt").read_text()


class TestDiskHealth:
    """Tests for disk_health script."""

    def test_missing_smartctl_returns_error(self, mock_context):
        """Returns exit code 2 when smartctl not available."""
        from scripts.baremetal import disk_health

        ctx = mock_context(tools_available=["lsblk"])
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 2
        assert any("smartctl" in e.lower() for e in output.errors)

    def test_all_disks_healthy(self, mock_context, smartctl_healthy):
        """Returns 0 when all disks pass SMART."""
        from scripts.baremetal import disk_health

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk\n",
                ("smartctl", "-H", "/dev/sda"): smartctl_healthy,
                ("smartctl", "-H", "/dev/sdb"): smartctl_healthy,
            }
        )
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["disks"]) == 2
        assert all(d["status"] == "PASSED" for d in output.data["disks"])

    def test_one_disk_failing(self, mock_context, smartctl_healthy, smartctl_failing):
        """Returns 1 when one disk fails SMART."""
        from scripts.baremetal import disk_health

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk\n",
                ("smartctl", "-H", "/dev/sda"): smartctl_healthy,
                ("smartctl", "-H", "/dev/sdb"): smartctl_failing,
            }
        )
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["disks"][0]["status"] == "PASSED"
        assert output.data["disks"][1]["status"] == "FAILED"

    def test_verbose_output(self, mock_context, smartctl_healthy):
        """--verbose shows additional details."""
        from scripts.baremetal import disk_health

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("smartctl", "-H", "/dev/sda"): smartctl_healthy,
            }
        )
        output = Output()

        exit_code = disk_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        # Verbose mode should include model info
        assert "model" in output.data["disks"][0]
```

**Step 2: Create the script**

```python
#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage, hardware]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_space_forecaster, disk_life_predictor, disk_io_latency_monitor]
#   brief: Check disk health using SMART attributes

"""
Check disk health using SMART (Self-Monitoring, Analysis and Reporting Technology).

Scans all disk devices and reports their SMART health status.
Returns exit code 1 if any disk is failing or has concerning attributes.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_disk_list(context: Context) -> list[str]:
    """Get list of disk devices."""
    result = context.run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"])
    disks = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "disk":
            disks.append(f"/dev/{parts[0]}")
    return disks


def check_smart_health(disk: str, context: Context) -> dict[str, Any]:
    """Check SMART health status for a disk."""
    result = context.run(["smartctl", "-H", disk], check=False)
    output = result.stdout

    status = "UNKNOWN"
    if "SMART overall-health self-assessment test result: PASSED" in output:
        status = "PASSED"
    elif "SMART overall-health self-assessment test result: FAILED" in output:
        status = "FAILED"
    elif "SMART support is: Unavailable" in output:
        status = "UNAVAILABLE"
    elif "SMART support is: Disabled" in output:
        status = "DISABLED"

    info = {
        "device": disk,
        "status": status,
    }

    # Extract model if present
    model_match = re.search(r"Device Model:\s+(.+)", output)
    if model_match:
        info["model"] = model_match.group(1).strip()

    # Extract serial if present
    serial_match = re.search(r"Serial Number:\s+(.+)", output)
    if serial_match:
        info["serial"] = serial_match.group(1).strip()

    return info


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Check disk health using SMART")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for smartctl
    if not context.check_tool("smartctl"):
        output.error("smartctl not found. Install smartmontools package.")
        return 2

    # Get disk list
    try:
        disks = get_disk_list(context)
    except Exception as e:
        output.error(f"Failed to list disks: {e}")
        return 2

    if not disks:
        output.warning("No disks found")
        output.emit({"disks": []})
        return 1

    # Check each disk
    results = []
    has_issues = False

    for disk in disks:
        info = check_smart_health(disk, context)
        results.append(info)

        if info["status"] in ("FAILED", "UNKNOWN"):
            has_issues = True

        if not opts.verbose:
            # Remove extra fields in non-verbose mode
            info.pop("model", None)
            info.pop("serial", None)

    output.emit({"disks": results})

    # Set summary
    passed = sum(1 for r in results if r["status"] == "PASSED")
    failed = sum(1 for r in results if r["status"] == "FAILED")
    output.set_summary(f"{passed} healthy, {failed} failing")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
```

**Step 3: Create directory and add to path for tests**

```bash
mkdir -p boxctl/scripts/baremetal
mkdir -p boxctl/tests/scripts/baremetal
touch boxctl/scripts/__init__.py
touch boxctl/scripts/baremetal/__init__.py
touch boxctl/tests/scripts/__init__.py
touch boxctl/tests/scripts/baremetal/__init__.py
```

**Step 4: Update conftest.py to add scripts to path**

Add to `boxctl/tests/conftest.py`:

```python
# Add scripts directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
```

**Step 5: Run tests**

```bash
cd boxctl && python -m pytest tests/scripts/baremetal/test_disk_health.py -v
```

Expected: All 4 tests PASS

**Step 6: Commit**

```bash
git add boxctl/scripts/ boxctl/tests/scripts/
git commit -m "feat(scripts): migrate disk_health with full test coverage"
```

---

## Phase 4: Additional Core Features

### Task 4.1: Implement Logging Module

**Files:**
- Create: `boxctl/boxctl/core/logging.py`
- Create: `boxctl/tests/core/test_logging.py`

(Similar TDD structure - tests first, then implementation)

Key functionality:
- Write JSONL logs to `~/var/log/boxctl/{date}/{script}.jsonl`
- Query logs by date, script, level
- Support `--tail` mode for following

### Task 4.2: Implement Profile Loader

**Files:**
- Create: `boxctl/boxctl/core/profiles.py`
- Create: `boxctl/tests/core/test_profiles.py`

Key functionality:
- Load profiles from `~/.config/boxctl/profiles/` and bundled `profiles/`
- Validate profile YAML schema
- Resolve script names to Script objects

### Task 4.3: Implement Doctor Command

**Files:**
- Modify: `boxctl/boxctl/cli.py`
- Create: `boxctl/tests/test_doctor.py`

Key functionality:
- Check all required tools across all scripts
- Report privilege capabilities
- Show script counts by category
- List user overrides

### Task 4.4: Implement Lint Command

**Files:**
- Modify: `boxctl/boxctl/cli.py`
- Create: `boxctl/boxctl/core/linter.py`
- Create: `boxctl/tests/core/test_linter.py`

Key functionality:
- Validate all script metadata headers
- Check for required fields
- Validate category format
- Report warnings/errors

---

## Phase 5: Script Migration

### Task 5.x: Migrate Remaining Scripts

For each script category, follow the disk_health pattern:

1. Collect real fixture outputs
2. Write comprehensive tests
3. Migrate script to new format
4. Verify 80% coverage
5. Commit

**Priority order:**
1. High-use baremetal scripts (disk, memory, cpu, network)
2. K8s scripts (pod, node, service)
3. Lower-priority scripts

---

## Phase 6: CI/CD & Release

### Task 6.1: GitHub Actions Test Workflow

**Files:**
- Create: `boxctl/.github/workflows/test.yml`

```yaml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -e ".[dev]"
      - name: Run unit tests with coverage
        run: |
          pytest tests/ \
            --ignore=tests/integration \
            --cov=boxctl \
            --cov-report=xml \
            --cov-fail-under=80
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  k8s-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start minikube
        uses: medyagh/setup-minikube@master
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -e ".[dev]"
      - name: Run k8s integration tests
        run: pytest tests/integration/k8s/ -v

  lint-scripts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -e ".[dev]"
      - name: Validate all script metadata
        run: python -m boxctl lint --all --strict
```

### Task 6.2: GitHub Actions Release Workflow

**Files:**
- Create: `boxctl/.github/workflows/release.yml`

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build distribution
        run: ./scripts/build.sh
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: boxctl-linux-amd64
          path: dist/boxctl-*.tar.gz

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - name: Create release
        uses: softprops/action-gh-release@v1
        with:
          files: boxctl-linux-amd64/*.tar.gz
```

### Task 6.3: Version Tagging Script

**Files:**
- Create: `boxctl/scripts/release.sh`

```bash
#!/bin/bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.0"
    exit 1
fi

# Update version in pyproject.toml
sed -i "s/^version = .*/version = \"$VERSION\"/" pyproject.toml

# Commit and tag
git add pyproject.toml
git commit -m "chore: release v$VERSION"
git tag "v$VERSION"

echo "Created tag v$VERSION"
echo "Run 'git push && git push --tags' to trigger release"
```

---

## Phase 7: Future Features (Deferred)

> **Note:** These features are deferred until core functionality is proven. Requirements gathering needed before implementation.

### Task 7.1: Runbook Engine

**Status:** DEFERRED

**Rationale:** Complex feature with unclear requirements. Core script running must be stable first.

**When to implement:**
- After 50+ scripts migrated and working
- After user feedback on orchestration needs
- After profiles are battle-tested

**Rough scope:**
- YAML workflow definitions
- Conditional execution (`when:`)
- Parallel groups
- Failure handling (`on_failure:`)

### Task 7.2: Scheduler / Cron Generator

**Status:** DEFERRED

**Rationale:** Cron management has many edge cases. Users can manually add cron entries initially.

**When to implement:**
- After logging is stable
- After profiles are in use
- When manual cron management becomes painful

**Rough scope:**
- `boxctl schedule --profile=X --every=1h`
- Crontab generation with conflict detection
- `boxctl crontab` to view managed entries

---

## Appendix: Script Migration Checklist

For each script migration:

- [ ] Capture real fixture outputs for tools used
- [ ] Write tests covering:
  - [ ] Missing required tools (exit code 2)
  - [ ] Healthy/normal case (exit code 0)
  - [ ] Warning case (exit code 1)
  - [ ] Edge cases specific to script
- [ ] Add header metadata
- [ ] Refactor to `run(args, output, context)` signature
- [ ] Use `context.run()` for all subprocess calls
- [ ] Use `context.read_file()` for file reads
- [ ] Use `context.check_tool()` for tool checks
- [ ] Verify 80% coverage
- [ ] Test standalone execution
- [ ] Commit with descriptive message
