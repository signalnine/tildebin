"""Tests for tcp_connection_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestTcpConnectionMonitor:
    """Tests for tcp_connection_monitor."""

    def test_healthy_connections(self, capsys):
        """Healthy connections return exit code 0."""
        from scripts.baremetal.tcp_connection_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_healthy.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "ESTABLISHED" in captured.out

    def test_high_timewait_warning(self, capsys):
        """High TIME_WAIT count returns exit code 1."""
        from scripts.baremetal.tcp_connection_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_high_timewait.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        # Lower threshold to trigger warning
        result = run(["--time-wait-warn", "3"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "TIME_WAIT" in captured.out

    def test_high_closewait_warning(self, capsys):
        """High CLOSE_WAIT count returns exit code 1."""
        from scripts.baremetal.tcp_connection_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_high_closewait.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        # Lower threshold to trigger warning
        result = run(["--close-wait-warn", "3"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CLOSE_WAIT" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.tcp_connection_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_healthy.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_connections" in data
        assert "state_counts" in data
        assert "status" in data
        assert "issues" in data

    def test_filter_by_state(self, capsys):
        """State filter works correctly."""
        from scripts.baremetal.tcp_connection_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_healthy.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--state", "LISTEN", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        # Only LISTEN connections should be counted
        assert data["total_connections"] == 2

    def test_invalid_state_exit_2(self, capsys):
        """Invalid state returns exit code 2."""
        from scripts.baremetal.tcp_connection_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_healthy.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--state", "INVALID_STATE"], output, context)

        assert result == 2

    def test_missing_proc_net_tcp(self, capsys):
        """Missing /proc/net/tcp returns exit code 2."""
        from scripts.baremetal.tcp_connection_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2
