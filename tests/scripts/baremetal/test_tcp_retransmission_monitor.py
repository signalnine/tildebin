"""Tests for tcp_retransmission_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestTcpRetransmissionMonitor:
    """Tests for tcp_retransmission_monitor."""

    def test_healthy_retransmission_rate(self, capsys):
        """Healthy retransmission rate returns exit code 0."""
        from scripts.baremetal.tcp_retransmission_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/snmp": load_fixture("snmp_healthy.txt"),
                "/proc/net/netstat": load_fixture("netstat_healthy.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_high_retransmission_rate(self, capsys):
        """High retransmission rate returns exit code 1."""
        from scripts.baremetal.tcp_retransmission_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/snmp": load_fixture("snmp_high_retrans.txt"),
                "/proc/net/netstat": load_fixture("netstat_healthy.txt"),
            }
        )
        output = Output()

        # Use lower threshold to trigger warning
        result = run(["--warn", "0.5", "--crit", "5.0"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "retransmission" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.tcp_retransmission_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/snmp": load_fixture("snmp_healthy.txt"),
                "/proc/net/netstat": load_fixture("netstat_healthy.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "status" in data
        assert "retransmission_pct" in data
        assert "metrics" in data
        assert "issues" in data

    def test_verbose_output(self, capsys):
        """Verbose mode shows detailed metrics."""
        from scripts.baremetal.tcp_retransmission_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/snmp": load_fixture("snmp_healthy.txt"),
                "/proc/net/netstat": load_fixture("netstat_healthy.txt"),
            }
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Detailed Metrics" in captured.out or "timeouts" in captured.out.lower()

    def test_invalid_thresholds_exit_2(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.tcp_retransmission_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/snmp": load_fixture("snmp_healthy.txt"),
            }
        )
        output = Output()

        # Warning >= critical is invalid
        result = run(["--warn", "5.0", "--crit", "1.0"], output, context)

        assert result == 2

    def test_missing_proc_snmp(self, capsys):
        """Missing /proc/net/snmp returns exit code 2."""
        from scripts.baremetal.tcp_retransmission_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_netstat_optional(self, capsys):
        """Script works without /proc/net/netstat."""
        from scripts.baremetal.tcp_retransmission_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/snmp": load_fixture("snmp_healthy.txt"),
                # No netstat file
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0  # Should still work
