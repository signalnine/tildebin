"""Tests for context_switch_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestContextSwitchMonitor:
    """Tests for context_switch_monitor."""

    def test_normal_context_switches_returns_0(self, capsys):
        """Normal context switch rate returns exit code 0."""
        from scripts.baremetal.context_switch_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_ctxt_normal.txt"),
                "/proc/vmstat": load_fixture("vmstat_ctxt_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out or "No issues" in captured.out

    def test_high_blocked_processes_returns_1(self, capsys):
        """High blocked process count returns exit code 1."""
        from scripts.baremetal.context_switch_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_ctxt_high.txt"),
                "/proc/vmstat": load_fixture("vmstat_ctxt_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "blocked" in captured.out.lower() or "WARNING" in captured.out or "CRITICAL" in captured.out

    def test_high_run_queue_returns_1(self, capsys):
        """High run queue depth returns exit code 1."""
        from scripts.baremetal.context_switch_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_ctxt_high.txt"),
            },
        )
        output = Output()

        # Use custom low thresholds to trigger warning
        result = run(["--run-queue-warn", "1.0", "--run-queue-crit", "3.0"], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.context_switch_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_ctxt_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "context_switches" in data
        assert "interrupts" in data
        assert "processes" in data
        assert "status" in data

    def test_table_output(self, capsys):
        """Table output format works correctly."""
        from scripts.baremetal.context_switch_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_ctxt_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Metric" in captured.out
        assert "Context switches" in captured.out

    def test_missing_stat_returns_2(self, capsys):
        """Missing /proc/stat returns exit code 2."""
        from scripts.baremetal.context_switch_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_suppresses_output(self, capsys):
        """warn-only flag suppresses output when no issues."""
        from scripts.baremetal.context_switch_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": load_fixture("stat_ctxt_normal.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""
