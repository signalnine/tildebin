"""Tests for hugepage_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestHugepageMonitor:
    """Tests for hugepage_monitor."""

    def test_healthy_hugepages_returns_0(self, capsys):
        """Healthy hugepage usage returns exit code 0."""
        from scripts.baremetal.hugepage_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_hugepages_healthy.txt"),
                "/sys/kernel/mm/transparent_hugepage/enabled": load_fixture("thp_enabled.txt"),
                "/sys/kernel/mm/transparent_hugepage/defrag": load_fixture("thp_defrag.txt"),
                "/proc/vmstat": load_fixture("vmstat_thp.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Hugepages" in captured.out

    def test_high_usage_returns_1(self, capsys):
        """High hugepage usage returns exit code 1."""
        from scripts.baremetal.hugepage_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_hugepages_high_usage.txt"),
                "/proc/vmstat": load_fixture("vmstat_thp.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "CRITICAL" in captured.out

    def test_no_hugepages_configured(self, capsys):
        """No hugepages configured shows INFO message."""
        from scripts.baremetal.hugepage_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_no_hugepages.txt"),
                "/proc/vmstat": load_fixture("vmstat_thp.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        # No hugepages is INFO, not WARNING, so returns 0
        assert result == 0
        captured = capsys.readouterr()
        assert "no static hugepages" in captured.out.lower() or "No hugepage issues" in captured.out

    def test_surplus_pages_detected(self, capsys):
        """Detects surplus hugepages (overcommit)."""
        from scripts.baremetal.hugepage_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_hugepages_surplus.txt"),
                "/proc/vmstat": load_fixture("vmstat_thp.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["hugepages"]["surplus"] == 64
        # Surplus is INFO, check issues
        surplus_issues = [i for i in data["issues"] if i["type"] == "surplus_pages"]
        assert len(surplus_issues) >= 1

    def test_json_output_format(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.hugepage_monitor import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_hugepages_healthy.txt"),
                "/sys/kernel/mm/transparent_hugepage/enabled": load_fixture("thp_enabled.txt"),
                "/proc/vmstat": load_fixture("vmstat_thp.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "hugepages" in data
        assert "transparent_huge_pages" in data
        assert "issues" in data
        assert "total" in data["hugepages"]
        assert "free" in data["hugepages"]
        assert "used" in data["hugepages"]
        assert "enabled" in data["transparent_huge_pages"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.hugepage_monitor import run

        # With healthy fixture (50% used), set warn=40 to trigger warning
        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_hugepages_healthy.txt"),
                "/proc/vmstat": load_fixture("vmstat_thp.txt"),
            },
        )
        output = Output()

        result = run(["--warn", "40", "--crit", "60"], output, context)

        assert result == 1  # Should warn at 50% usage
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_missing_meminfo_returns_2(self, capsys):
        """Missing /proc/meminfo returns exit code 2."""
        from scripts.baremetal.hugepage_monitor import run

        context = MockContext(
            file_contents={},  # No files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
