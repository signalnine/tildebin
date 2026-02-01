"""Tests for softnet_backlog_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSoftnetBacklogMonitor:
    """Tests for softnet_backlog_monitor."""

    def test_healthy_stats(self, capsys):
        """Healthy softnet stats return exit code 0."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "healthy" in captured.out.lower() or "OK" in captured.out

    def test_packet_drops_warning(self, capsys):
        """Packet drops trigger warning."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_drops.txt"),
            },
        )
        output = Output()

        # Drops in this fixture exceed default warning threshold of 1
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "drop" in captured.out.lower()

    def test_time_squeeze_warning(self, capsys):
        """Time squeeze events trigger warning."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_time_squeeze.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "squeeze" in captured.out.lower()

    def test_critical_stats(self, capsys):
        """Critical stats return exit code 1."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_critical.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "critical" in captured.out.lower() or "ISSUES" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "totals" in data
        assert "per_cpu" in data
        assert "status" in data
        assert "total_processed" in data["totals"]
        assert "total_dropped" in data["totals"]

    def test_verbose_shows_per_cpu(self, capsys):
        """Verbose mode shows per-CPU statistics."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Per-CPU" in captured.out

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_drops.txt"),
            },
        )
        output = Output()

        # With very high thresholds, drops shouldn't trigger warnings
        result = run(["--drop-warn", "100000", "--drop-crit", "1000000"], output, context)

        assert result == 0

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/softnet_stat": load_fixture("softnet_stat_healthy.txt"),
            },
        )
        output = Output()

        # warn > crit is invalid
        result = run(["--drop-warn", "100", "--drop-crit", "10"], output, context)

        assert result == 2

    def test_missing_proc_file(self, capsys):
        """Missing /proc/net/softnet_stat returns exit code 2."""
        from scripts.baremetal.softnet_backlog_monitor import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
