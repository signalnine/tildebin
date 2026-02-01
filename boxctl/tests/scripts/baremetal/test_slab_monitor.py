"""Tests for slab_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSlabMonitor:
    """Tests for slab_monitor."""

    def test_healthy_slab_returns_0(self, capsys):
        """Healthy slab usage returns exit code 0."""
        from scripts.baremetal.slab_monitor import run

        context = MockContext(
            file_contents={
                "/proc/slabinfo": load_fixture("slabinfo_healthy.txt"),
                "/proc/meminfo": load_fixture("meminfo_for_slab.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Kernel Slab Allocator Status" in captured.out

    def test_high_dentry_cache_returns_1(self, capsys):
        """High dentry cache usage returns exit code 1."""
        from scripts.baremetal.slab_monitor import run

        context = MockContext(
            file_contents={
                "/proc/slabinfo": load_fixture("slabinfo_high_dentry.txt"),
                "/proc/meminfo": load_fixture("meminfo_for_slab.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "dentry" in captured.out.lower()

    def test_low_active_ratio_warning(self, capsys):
        """Low active ratio triggers warning."""
        from scripts.baremetal.slab_monitor import run

        context = MockContext(
            file_contents={
                "/proc/slabinfo": load_fixture("slabinfo_low_ratio.txt"),
                "/proc/meminfo": load_fixture("meminfo_for_slab.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "active ratio" in captured.out.lower() or "WARNING" in captured.out

    def test_json_output_format(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.slab_monitor import run

        context = MockContext(
            file_contents={
                "/proc/slabinfo": load_fixture("slabinfo_healthy.txt"),
                "/proc/meminfo": load_fixture("meminfo_for_slab.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "top_caches" in data
        assert "total_caches" in data["summary"]
        assert "total_slab_mb" in data["summary"]
        assert "slab_pct_of_memory" in data["summary"]

    def test_top_caches_limit(self, capsys):
        """--top limits number of caches shown."""
        from scripts.baremetal.slab_monitor import run

        context = MockContext(
            file_contents={
                "/proc/slabinfo": load_fixture("slabinfo_healthy.txt"),
                "/proc/meminfo": load_fixture("meminfo_for_slab.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json", "--top", "5"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert len(data["top_caches"]) <= 5

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.slab_monitor import run

        # Use the critical fixture which has high slab usage
        context = MockContext(
            file_contents={
                "/proc/slabinfo": load_fixture("slabinfo_critical.txt"),
                "/proc/meminfo": load_fixture("meminfo_for_slab.txt"),
            },
        )
        output = Output()

        # Set low threshold to trigger warning from the high-usage fixture
        result = run(["--warn-pct", "10", "--crit-pct", "20"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "CRITICAL" in captured.out

    def test_missing_slabinfo_returns_2(self, capsys):
        """Missing slabinfo returns exit code 2."""
        from scripts.baremetal.slab_monitor import run

        context = MockContext(
            file_contents={},  # No files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
