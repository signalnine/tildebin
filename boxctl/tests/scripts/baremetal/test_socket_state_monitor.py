"""Tests for socket_state_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSocketStateMonitor:
    """Tests for socket_state_monitor."""

    def test_healthy_socket_states(self, capsys):
        """Healthy socket states return exit code 0."""
        from scripts.baremetal.socket_state_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_socket_healthy.txt"),
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
        from scripts.baremetal.socket_state_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_socket_high_timewait.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        # Lower threshold to trigger warning
        result = run(["--time-wait", "5"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "TIME_WAIT" in captured.out

    def test_syn_recv_warning(self, capsys):
        """High SYN_RECV count returns exit code 1."""
        from scripts.baremetal.socket_state_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_socket_syn_recv.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        # Lower threshold to trigger warning
        result = run(["--syn-recv", "3"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "SYN_RECV" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.socket_state_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_socket_healthy.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "state_counts" in data
        assert "total_sockets" in data
        assert "issues" in data
        assert "status" in data

    def test_table_output(self, capsys):
        """Table output displays properly."""
        from scripts.baremetal.socket_state_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_socket_healthy.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "State" in captured.out
        assert "Count" in captured.out

    def test_missing_proc_net_tcp(self, capsys):
        """Missing /proc/net/tcp returns exit code 2."""
        from scripts.baremetal.socket_state_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_no_output_when_healthy(self, capsys):
        """--warn-only produces no output when healthy."""
        from scripts.baremetal.socket_state_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_socket_healthy.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""
