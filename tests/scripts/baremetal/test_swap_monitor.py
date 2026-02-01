"""Tests for swap_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSwapMonitor:
    """Tests for swap_monitor."""

    def test_healthy_swap(self, capsys):
        """Healthy swap returns exit code 0."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/vmstat": load_fixture("vmstat_normal.txt"),
            },
        )
        output = Output()

        # SwapFree: 4000000, SwapTotal: 4096000 = ~2.3% used (healthy)
        result = run([], output, context)

        assert result == 0

    def test_high_swap_warning(self, capsys):
        """High swap usage returns exit code 1."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_high_swap.txt"),
                "/proc/vmstat": load_fixture("vmstat_normal.txt"),
            },
        )
        output = Output()

        # SwapFree: 1024000, SwapTotal: 4096000 = 75% used (high)
        result = run([], output, context)

        assert result == 1

    def test_critical_swap(self, capsys):
        """Critical swap usage returns exit code 1."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_critical.txt"),
                "/proc/vmstat": load_fixture("vmstat_normal.txt"),
            },
        )
        output = Output()

        # SwapFree: 512000, SwapTotal: 4096000 = 87.5% used (critical)
        result = run([], output, context)

        assert result == 1

    def test_no_swap_configured(self, capsys):
        """No swap configured returns exit code 0."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_no_swap.txt"),
                "/proc/vmstat": load_fixture("vmstat_normal.txt"),
            },
        )
        output = Output()

        # SwapTotal: 0 = no swap (intentional)
        result = run([], output, context)

        # No swap is not an error, just informational
        assert result == 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/vmstat": load_fixture("vmstat_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "swap" in data
        assert "memory" in data
        assert "issues" in data
        assert "total_kb" in data["swap"]
        assert "used_kb" in data["swap"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_high_swap.txt"),  # 75% used
                "/proc/vmstat": load_fixture("vmstat_normal.txt"),
            },
        )
        output = Output()

        # With higher thresholds, should be OK
        result = run(["--warn", "80", "--crit", "90"], output, context)

        assert result == 0

    def test_verbose_shows_vmstat(self, capsys):
        """Verbose mode shows vmstat info."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/vmstat": load_fixture("vmstat_normal.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        # Should mention memory or swap activity
        assert "available" in captured.out.lower() or "memory" in captured.out.lower()

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
            },
        )
        output = Output()

        # Warning >= critical is invalid
        result = run(["--warn", "80", "--crit", "60"], output, context)

        assert result == 2

    def test_missing_meminfo(self, capsys):
        """Missing /proc/meminfo returns exit code 2."""
        from scripts.baremetal.swap_monitor import run

        context = MockContext(
            file_contents={},  # No meminfo
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
