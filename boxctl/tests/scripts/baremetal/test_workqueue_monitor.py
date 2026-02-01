"""Tests for workqueue_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestWorkqueueMonitor:
    """Tests for workqueue_monitor."""

    def test_healthy_kworkers(self, capsys):
        """Healthy kworker stats return exit code 0."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={
                "/proc/kworker_stats": load_fixture("kworker_stats_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out.lower()

    def test_uninterruptible_warning(self, capsys):
        """Uninterruptible kworkers above warning threshold."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={
                "/proc/kworker_stats": load_fixture("kworker_stats_uninterruptible.txt"),
            },
        )
        output = Output()

        # This fixture has 6 D-state kworkers, above default warning of 5
        # Warnings return exit code 0 (only issues return 1)
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "uninterruptible" in captured.out.lower()
        assert "WARNINGS" in captured.out

    def test_uninterruptible_critical(self, capsys):
        """Uninterruptible kworkers above critical threshold."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={
                "/proc/kworker_stats": load_fixture("kworker_stats_critical.txt"),
            },
        )
        output = Output()

        # This fixture has 12 D-state kworkers, above default critical of 10
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "critical" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={
                "/proc/kworker_stats": load_fixture("kworker_stats_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "kworker_stats" in data
        assert "status" in data
        assert "total_kworkers" in data["kworker_stats"]
        assert "uninterruptible" in data["kworker_stats"]

    def test_verbose_shows_distribution(self, capsys):
        """Verbose mode shows kworker distribution."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={
                "/proc/kworker_stats": load_fixture("kworker_stats_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Distribution" in captured.out

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={
                "/proc/kworker_stats": load_fixture("kworker_stats_uninterruptible.txt"),
            },
        )
        output = Output()

        # With higher thresholds, should be healthy
        result = run(["--uninterruptible-warn", "20", "--uninterruptible-crit", "30"], output, context)

        assert result == 0

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={
                "/proc/kworker_stats": load_fixture("kworker_stats_healthy.txt"),
            },
        )
        output = Output()

        # warn >= crit is invalid
        result = run(["--uninterruptible-warn", "10", "--uninterruptible-crit", "5"], output, context)

        assert result == 2

    def test_missing_proc_defaults_to_empty(self, capsys):
        """Missing /proc/kworker_stats defaults to empty stats."""
        from scripts.baremetal.workqueue_monitor import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        # Should succeed with empty stats
        assert result == 0
