"""Tests for ephemeral_port_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestEphemeralPortMonitor:
    """Tests for ephemeral_port_monitor."""

    def test_healthy_usage(self, capsys):
        """Healthy ephemeral port usage returns exit code 0."""
        from scripts.baremetal.ephemeral_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/ipv4/ip_local_port_range": load_fixture(
                    "ephemeral_port_range.txt"
                ),
                "/proc/net/tcp": load_fixture("ephemeral_tcp_healthy.txt"),
                "/proc/net/tcp6": load_fixture("ephemeral_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out.lower()

    def test_high_usage_warning(self, capsys):
        """High usage triggers warning."""
        from scripts.baremetal.ephemeral_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/ipv4/ip_local_port_range": "32768\t32773\n",  # Only 6 ports
                "/proc/net/tcp": load_fixture("ephemeral_tcp_high_usage.txt"),
                "/proc/net/tcp6": load_fixture("ephemeral_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "CRITICAL" in captured.out

    def test_time_wait_accumulation(self, capsys):
        """TIME_WAIT accumulation triggers warning."""
        from scripts.baremetal.ephemeral_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/ipv4/ip_local_port_range": "32768\t32778\n",  # Only 11 ports
                "/proc/net/tcp": load_fixture("ephemeral_tcp_time_wait.txt"),
                "/proc/net/tcp6": load_fixture("ephemeral_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--time-wait-percent", "10"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "TIME_WAIT" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.ephemeral_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/ipv4/ip_local_port_range": load_fixture(
                    "ephemeral_port_range.txt"
                ),
                "/proc/net/tcp": load_fixture("ephemeral_tcp_healthy.txt"),
                "/proc/net/tcp6": load_fixture("ephemeral_tcp6_empty.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "ephemeral_ports" in data
        assert "used" in data["ephemeral_ports"]
        assert "free" in data["ephemeral_ports"]
        assert "usage_percent" in data["ephemeral_ports"]
        assert "issues" in data

    def test_custom_thresholds(self, capsys):
        """Custom thresholds work correctly."""
        from scripts.baremetal.ephemeral_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/ipv4/ip_local_port_range": "32768\t32773\n",  # 6 ports
                "/proc/net/tcp": load_fixture("ephemeral_tcp_healthy.txt"),  # 2 ephemeral
                "/proc/net/tcp6": load_fixture("ephemeral_tcp6_empty.txt"),
            }
        )
        output = Output()

        # 2/6 = 33%, so with --warning 20 --critical 40, should warn
        result = run(["--warning", "20", "--critical", "40"], output, context)

        assert result == 1

    def test_missing_proc_tcp_exit_2(self, capsys):
        """Missing /proc/net/tcp returns exit code 2."""
        from scripts.baremetal.ephemeral_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/ipv4/ip_local_port_range": "32768\t60999\n",
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_invalid_thresholds_exit_2(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.ephemeral_port_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/ipv4/ip_local_port_range": "32768\t60999\n",
                "/proc/net/tcp": load_fixture("ephemeral_tcp_healthy.txt"),
                "/proc/net/tcp6": load_fixture("ephemeral_tcp6_empty.txt"),
            }
        )
        output = Output()

        # warning >= critical is invalid
        result = run(["--warning", "90", "--critical", "80"], output, context)

        assert result == 2
