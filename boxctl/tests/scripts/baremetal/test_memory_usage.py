"""Tests for memory_usage script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestMemoryUsage:
    """Tests for memory_usage."""

    def test_healthy_memory(self, capsys):
        """Healthy memory returns exit code 0."""
        from scripts.baremetal.memory_usage import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
            },
        )
        output = Output()

        # MemAvailable: 8192000, MemTotal: 16384000 = 50% available (healthy)
        result = run([], output, context)

        assert result == 0

    def test_low_memory_warning(self, capsys):
        """Low memory returns warning (exit code 1)."""
        from scripts.baremetal.memory_usage import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_high_swap.txt"),
            },
        )
        output = Output()

        # MemAvailable: 2048000, MemTotal: 16384000 = 12.5% available (warning level)
        result = run([], output, context)

        assert result == 1

    def test_critical_memory(self, capsys):
        """Critical memory returns exit code 1."""
        from scripts.baremetal.memory_usage import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_critical.txt"),
            },
        )
        output = Output()

        # MemAvailable: 512000, MemTotal: 16384000 = 3.1% available (critical)
        result = run([], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.memory_usage import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_kb" in data
        assert "available_kb" in data
        assert "used_kb" in data
        assert "available_percent" in data
        assert "status" in data

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.memory_usage import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_high_swap.txt"),  # 12.5% available
            },
        )
        output = Output()

        # With lower thresholds, should still be warning
        # but with warn=5, crit=2, should be OK
        result = run(["--warn", "10", "--crit", "5"], output, context)

        assert result == 0

    def test_verbose_shows_breakdown(self, capsys):
        """Verbose mode shows memory breakdown."""
        from scripts.baremetal.memory_usage import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        # Should show buffers/cached info
        assert "buffer" in captured.out.lower() or "cache" in captured.out.lower()

    def test_missing_meminfo(self, capsys):
        """Missing /proc/meminfo returns exit code 2."""
        from scripts.baremetal.memory_usage import run

        context = MockContext(
            file_contents={},  # No meminfo
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
