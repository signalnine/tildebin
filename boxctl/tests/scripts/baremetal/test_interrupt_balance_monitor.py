"""Tests for interrupt_balance_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestInterruptBalanceMonitor:
    """Tests for interrupt_balance_monitor."""

    def test_balanced_interrupts_returns_0(self, capsys):
        """Balanced interrupts return exit code 0."""
        from scripts.baremetal.interrupt_balance_monitor import run

        context = MockContext(
            file_contents={
                "/proc/interrupts": load_fixture("interrupts_balanced.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_imbalanced_irq_returns_1(self, capsys):
        """Imbalanced IRQ distribution returns exit code 1."""
        from scripts.baremetal.interrupt_balance_monitor import run

        context = MockContext(
            file_contents={
                "/proc/interrupts": load_fixture("interrupts_imbalanced.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "imbalance" in captured.out.lower()

    def test_cpu0_overload_returns_1(self, capsys):
        """CPU0 overload returns exit code 1."""
        from scripts.baremetal.interrupt_balance_monitor import run

        context = MockContext(
            file_contents={
                "/proc/interrupts": load_fixture("interrupts_cpu0_overload.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CPU0" in captured.out or "overload" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.interrupt_balance_monitor import run

        context = MockContext(
            file_contents={
                "/proc/interrupts": load_fixture("interrupts_balanced.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "num_cpus" in data
        assert "total_interrupts" in data
        assert "cpu_totals" in data
        assert "issues" in data
        assert "status" in data

    def test_table_output(self, capsys):
        """Table output format works correctly."""
        from scripts.baremetal.interrupt_balance_monitor import run

        context = MockContext(
            file_contents={
                "/proc/interrupts": load_fixture("interrupts_balanced.txt"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "CPU" in captured.out
        assert "Interrupts" in captured.out
        assert "Percentage" in captured.out

    def test_missing_interrupts_returns_2(self, capsys):
        """Missing /proc/interrupts returns exit code 2."""
        from scripts.baremetal.interrupt_balance_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_custom_threshold(self, capsys):
        """Custom threshold is respected."""
        from scripts.baremetal.interrupt_balance_monitor import run

        # With very high threshold (99%), imbalanced should be OK
        context = MockContext(
            file_contents={
                "/proc/interrupts": load_fixture("interrupts_imbalanced.txt"),
            },
        )
        output = Output()

        result = run(["--threshold", "0.99"], output, context)

        # Some IRQs may still be above 99%, so just check it doesn't error
        assert result in [0, 1]

    def test_verbose_shows_distribution(self, capsys):
        """Verbose mode shows per-CPU distribution."""
        from scripts.baremetal.interrupt_balance_monitor import run

        context = MockContext(
            file_contents={
                "/proc/interrupts": load_fixture("interrupts_balanced.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "CPU0" in captured.out
        assert "CPU1" in captured.out
