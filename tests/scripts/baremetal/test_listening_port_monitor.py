"""Tests for listening_port_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestListeningPortMonitor:
    """Tests for listening_port_monitor."""

    def test_healthy_ports(self, capsys):
        """Healthy listening ports return exit code 0."""
        from scripts.baremetal.listening_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_listening.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_listening.txt"),
                "/proc/net/udp": load_fixture("net_udp_listening.txt"),
                "/proc/net/udp6": load_fixture("net_udp6_listening.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "listening" in captured.out.lower()

    def test_expected_ports_missing(self, capsys):
        """Missing expected ports return exit code 1."""
        from scripts.baremetal.listening_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_listening.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_listening.txt"),
                "/proc/net/udp": load_fixture("net_udp_listening.txt"),
                "/proc/net/udp6": load_fixture("net_udp6_listening.txt"),
            }
        )
        output = Output()

        # Port 3306 is not in fixtures
        result = run(["--expected", "22,80,3306"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "3306" in captured.out

    def test_unexpected_ports_found(self, capsys):
        """Unexpected ports return exit code 1."""
        from scripts.baremetal.listening_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_listening.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_listening.txt"),
                "/proc/net/udp": load_fixture("net_udp_listening.txt"),
                "/proc/net/udp6": load_fixture("net_udp6_listening.txt"),
            }
        )
        output = Output()

        # Port 80 is in the fixtures
        result = run(["--unexpected", "80"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "80" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.listening_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_listening.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_listening.txt"),
                "/proc/net/udp": load_fixture("net_udp_listening.txt"),
                "/proc/net/udp6": load_fixture("net_udp6_listening.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "listening_ports" in data
        assert "summary" in data
        assert "issues" in data
        assert "status" in data

    def test_tcp_only_filter(self, capsys):
        """--tcp-only shows only TCP ports."""
        from scripts.baremetal.listening_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_listening.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_listening.txt"),
                "/proc/net/udp": load_fixture("net_udp_listening.txt"),
                "/proc/net/udp6": load_fixture("net_udp6_listening.txt"),
            }
        )
        output = Output()

        result = run(["--tcp-only", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # All ports should be TCP
        for port in data["listening_ports"]:
            assert port["protocol"].startswith("tcp")

    def test_missing_proc_net_tcp(self, capsys):
        """Missing /proc/net/tcp returns exit code 2."""
        from scripts.baremetal.listening_port_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_conflicting_options_exit_2(self, capsys):
        """Conflicting options return exit code 2."""
        from scripts.baremetal.listening_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": load_fixture("net_tcp_listening.txt"),
                "/proc/net/tcp6": load_fixture("net_tcp6_listening.txt"),
                "/proc/net/udp": load_fixture("net_udp_listening.txt"),
                "/proc/net/udp6": load_fixture("net_udp6_listening.txt"),
            }
        )
        output = Output()

        # Cannot specify both --tcp-only and --udp-only
        result = run(["--tcp-only", "--udp-only"], output, context)

        assert result == 2
