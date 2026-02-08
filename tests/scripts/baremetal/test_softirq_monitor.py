"""Tests for softirq_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSoftirqMonitor:
    """Tests for softirq_monitor."""

    def test_normal_distribution(self, capsys):
        """Normal balanced softirq distribution returns exit code 0."""
        from scripts.baremetal.softirq_monitor import run

        context = MockContext(
            file_contents={
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "balanced" in captured.out.lower() or "OK" in captured.out

    def test_imbalanced_net_rx(self, capsys):
        """Imbalanced NET_RX returns exit code 1."""
        from scripts.baremetal.softirq_monitor import run

        context = MockContext(
            file_contents={
                "/proc/softirqs": load_fixture("softirqs_imbalanced.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "NET_RX" in captured.out
        assert "CPU0" in captured.out

    def test_single_cpu_no_imbalance(self, capsys):
        """Single CPU system should not report imbalance."""
        from scripts.baremetal.softirq_monitor import run

        context = MockContext(
            file_contents={
                "/proc/softirqs": load_fixture("softirqs_single_cpu.txt"),
            },
            env={"cpu_count": "1"},
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.softirq_monitor import run

        context = MockContext(
            file_contents={
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "cpu_count" in data
        assert "softirq_types" in data
        assert "totals" in data
        assert "status" in data
        assert "issues" in data

    def test_verbose_shows_totals(self, capsys):
        """Verbose mode shows softirq totals."""
        from scripts.baremetal.softirq_monitor import run

        context = MockContext(
            file_contents={
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Totals:" in captured.out
        assert "Net Rx" in captured.out

    def test_custom_imbalance_threshold(self, capsys):
        """Custom imbalance threshold affects detection."""
        from scripts.baremetal.softirq_monitor import run

        # With a very high threshold, the imbalanced fixture should pass
        context = MockContext(
            file_contents={
                "/proc/softirqs": load_fixture("softirqs_imbalanced.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run(["--imbalance", "100.0"], output, context)

        assert result == 0

    def test_invalid_imbalance_threshold(self, capsys):
        """Invalid imbalance threshold returns exit code 2."""
        from scripts.baremetal.softirq_monitor import run

        context = MockContext(
            file_contents={
                "/proc/softirqs": load_fixture("softirqs_normal.txt"),
            },
            env={"cpu_count": "4"},
        )
        output = Output()

        # Threshold must be > 1
        result = run(["--imbalance", "0.5"], output, context)

        assert result == 2

    def test_missing_proc_softirqs(self, capsys):
        """Missing /proc/softirqs returns exit code 2."""
        from scripts.baremetal.softirq_monitor import run

        context = MockContext(
            file_contents={},
            env={"cpu_count": "4"},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
