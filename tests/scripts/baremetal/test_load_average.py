"""Tests for load_average_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestLoadAverageMonitor:
    """Tests for load_average_monitor."""

    def test_normal_load(self, capsys):
        """Normal load returns exit code 0."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={
                "/proc/loadavg": load_fixture("loadavg_normal.txt"),
            },
            env={"cpu_count": "4"},  # 4 CPUs
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # With 4 CPUs and load 0.25, normalized = 0.0625 per CPU (healthy)

    def test_high_load_warning(self, capsys):
        """High load returns exit code 1 with warnings."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={
                "/proc/loadavg": load_fixture("loadavg_high.txt"),
            },
            env={"cpu_count": "8"},  # 8 CPUs
        )
        output = Output()

        # Load 8.5/8 = 1.0625 per CPU (above warning threshold 0.7)
        result = run([], output, context)

        assert result == 1

    def test_critical_load(self, capsys):
        """Critical load returns exit code 1 with issues."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={
                "/proc/loadavg": load_fixture("loadavg_critical.txt"),
            },
            env={"cpu_count": "4"},  # 4 CPUs
        )
        output = Output()

        # Load 16/4 = 4.0 per CPU (way above critical threshold)
        result = run([], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={
                "/proc/loadavg": load_fixture("loadavg_normal.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "load_averages" in data
        assert "cpu" in data
        assert "normalized_load" in data
        assert "status" in data

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={
                "/proc/loadavg": load_fixture("loadavg_high.txt"),  # 8.5 load
            },
            env={"cpu_count": "8"},  # 1.0625 per CPU
        )
        output = Output()

        # With higher threshold, should be OK
        result = run(["--warning", "2.0", "--critical", "3.0"], output, context)

        assert result == 0

    def test_verbose_shows_processes(self, capsys):
        """Verbose mode shows process counts."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={
                "/proc/loadavg": load_fixture("loadavg_normal.txt"),  # has 1/256 processes
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "running" in captured.out.lower() or "processes" in captured.out.lower()

    def test_invalid_thresholds_exit_2(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={
                "/proc/loadavg": load_fixture("loadavg_normal.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        # Warning >= critical is invalid
        result = run(["--warning", "2.0", "--critical", "1.0"], output, context)

        assert result == 2

    def test_missing_proc_loadavg(self, capsys):
        """Missing /proc/loadavg returns exit code 2."""
        from scripts.baremetal.load_average import run

        context = MockContext(
            file_contents={},  # No loadavg file
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
