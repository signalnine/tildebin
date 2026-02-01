"""Tests for dmesg_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "kernel"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestDmesgAnalyzer:
    """Tests for dmesg_analyzer script."""

    def test_clean_dmesg_returns_0(self, capsys):
        """Clean dmesg returns exit code 0."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_clean.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["summary"]["critical_count"] == 0
        assert output.data["summary"]["warning_count"] == 0

    def test_disk_errors_detected(self, capsys):
        """Disk errors are detected as critical."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_errors.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert "disk" in output.data["findings"]
        assert output.data["summary"]["critical_count"] > 0

    def test_memory_errors_detected(self, capsys):
        """Memory errors (EDAC/ECC) are detected."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_errors.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert "memory" in output.data["findings"]

    def test_filesystem_errors_detected(self, capsys):
        """Filesystem errors are detected."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_errors.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert "filesystem" in output.data["findings"]

    def test_mce_errors_detected(self, capsys):
        """Machine check exceptions are detected."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_errors.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert "cpu" in output.data["findings"]

    def test_missing_dmesg_returns_2(self, capsys):
        """Missing dmesg returns exit code 2."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=[],  # No dmesg
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_clean.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "findings" in data
        assert "total_issues" in data["summary"]
        assert "critical_count" in data["summary"]
        assert "warning_count" in data["summary"]

    def test_warn_only_suppresses_clean_output(self, capsys):
        """--warn-only suppresses output for clean dmesg."""
        from scripts.baremetal.dmesg_analyzer import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_clean.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""
