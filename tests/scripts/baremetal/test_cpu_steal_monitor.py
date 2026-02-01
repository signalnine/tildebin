"""Tests for cpu_steal_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestCpuStealMonitor:
    """Tests for cpu_steal_monitor."""

    def test_normal_steal_returns_0(self, capsys):
        """Normal steal time returns exit code 0."""
        from scripts.baremetal.cpu_steal_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_steal_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_warning_steal_returns_1(self, capsys):
        """Warning-level steal time returns exit code 1."""
        from scripts.baremetal.cpu_steal_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_steal_warning.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "warning" in captured.out.lower()

    def test_critical_steal_returns_1(self, capsys):
        """Critical steal time returns exit code 1."""
        from scripts.baremetal.cpu_steal_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_steal_critical.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out or "critical" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.cpu_steal_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_steal_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "status" in data
        assert "summary" in data
        assert "cpus" in data
        assert "cpu" in data["cpus"]

    def test_table_output(self, capsys):
        """Table output format works correctly."""
        from scripts.baremetal.cpu_steal_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_steal_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "CPU" in captured.out
        assert "Steal" in captured.out

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.cpu_steal_monitor import run

        # With high thresholds, warning-level steal should be OK
        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_steal_warning.txt"),
            },
        )
        output = Output()

        result = run(["--warn", "20", "--crit", "30"], output, context)

        assert result == 0

    def test_missing_stat_returns_2(self, capsys):
        """Missing /proc/stat returns exit code 2."""
        from scripts.baremetal.cpu_steal_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_invalid_thresholds_returns_2(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.cpu_steal_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_steal_normal.txt"),
            },
        )
        output = Output()

        # warn >= crit is invalid
        result = run(["--warn", "20", "--crit", "10"], output, context)

        assert result == 2
