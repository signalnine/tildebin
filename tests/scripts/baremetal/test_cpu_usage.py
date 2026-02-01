"""Tests for cpu_usage script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestCpuUsage:
    """Tests for cpu_usage."""

    def test_normal_cpu(self, capsys):
        """Normal CPU usage returns exit code 0."""
        from scripts.baremetal.cpu_usage import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_normal.txt"),
            },
        )
        output = Output()

        # Normal CPU usage (~13% busy, ~86% idle)
        result = run([], output, context)

        assert result == 0

    def test_high_cpu_warning(self, capsys):
        """High CPU usage returns warning (exit code 1)."""
        from scripts.baremetal.cpu_usage import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_high_cpu.txt"),
            },
        )
        output = Output()

        # High CPU usage (~90% busy, ~10% idle)
        result = run([], output, context)

        assert result == 1

    def test_high_iowait(self, capsys):
        """High iowait returns warning (exit code 1)."""
        from scripts.baremetal.cpu_usage import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_high_iowait.txt"),
            },
        )
        output = Output()

        # High iowait (~32%)
        result = run([], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.cpu_usage import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "user" in data
        assert "system" in data
        assert "idle" in data
        assert "iowait" in data
        assert "status" in data

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.cpu_usage import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_high_cpu.txt"),  # ~90% busy
            },
        )
        output = Output()

        # With higher idle threshold, should be OK
        result = run(["--warn-idle", "5", "--crit-idle", "2"], output, context)

        assert result == 0

    def test_verbose_shows_per_cpu(self, capsys):
        """Verbose mode shows per-CPU stats."""
        from scripts.baremetal.cpu_usage import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_normal.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        # Should show cpu0, cpu1, etc.
        assert "cpu0" in captured.out.lower() or "per" in captured.out.lower()

    def test_missing_stat(self, capsys):
        """Missing /proc/stat returns exit code 2."""
        from scripts.baremetal.cpu_usage import run

        context = MockContext(
            file_contents={},  # No stat
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
