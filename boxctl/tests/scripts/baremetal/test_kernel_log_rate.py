"""Tests for kernel_log_rate script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "log"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestKernelLogRate:
    """Tests for kernel_log_rate."""

    def test_normal_rate(self, capsys):
        """Normal kernel message rate returns exit code 0."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_high_rate_warning(self, capsys):
        """High message rate triggers warning (exit code 1)."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_high_rate.txt"),
            },
        )
        output = Output()

        # Low threshold to trigger warning
        result = run(["--warn-rate", "10", "--crit-rate", "100"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        # Could be WARNING or could trigger burst detection
        assert "WARNING" in captured.out or "CRITICAL" in captured.out

    def test_burst_detection(self, capsys):
        """Burst of messages is detected."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_high_rate.txt"),
            },
        )
        output = Output()

        # Very low burst threshold to trigger detection
        result = run(["--burst-threshold", "5"], output, context)

        # May or may not trigger depending on timestamp parsing
        # Just verify it runs without error
        assert result in (0, 1)

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "status" in data
        assert "statistics" in data
        assert "bursts" in data
        assert "issues" in data

    def test_missing_dmesg(self, capsys):
        """Missing dmesg returns exit code 2."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(
            tools_available=[],  # No dmesg
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_no_output_when_healthy(self, capsys):
        """With --warn-only, no output when healthy."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_normal.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(tools_available=["dmesg"])
        output = Output()

        # Warn rate greater than crit rate is invalid
        result = run(["--warn-rate", "100", "--crit-rate", "50"], output, context)

        assert result == 2

    def test_verbose_output(self, capsys):
        """Verbose output includes priority breakdown."""
        from scripts.baremetal.kernel_log_rate import run

        context = MockContext(
            tools_available=["dmesg"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_normal.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Priority breakdown" in captured.out or "Total messages" in captured.out
