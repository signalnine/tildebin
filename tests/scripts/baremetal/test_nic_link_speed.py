"""Tests for nic_link_speed script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNicLinkSpeed:
    """Tests for nic_link_speed."""

    def test_healthy_interface_10g(self, capsys):
        """Interface at full 10Gb/s speed returns exit code 0."""
        from scripts.baremetal.nic_link_speed import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
            },
        )
        # Override glob to return our interface
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "10000Mb/s" in captured.out or "10Gb/s" in captured.out

    def test_slow_interface_warning(self, capsys):
        """Interface at 100Mb/s when max is 10Gb/s returns exit code 1."""
        from scripts.baremetal.nic_link_speed import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "eth0"): load_fixture("ethtool_eth1_slow.txt"),
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "100Mb/s" in captured.out
        assert "WARNING" in captured.out or "suboptimal" in captured.out.lower()

    def test_half_duplex_issue(self, capsys):
        """Half duplex detected returns exit code 1."""
        from scripts.baremetal.nic_link_speed import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "eth0"): load_fixture("ethtool_eth2_halfduplex.txt"),
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Half" in captured.out

    def test_no_link_detected(self, capsys):
        """No link detected returns status no_link."""
        from scripts.baremetal.nic_link_speed import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "eth0"): load_fixture("ethtool_eth3_nolink.txt"),
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "No link" in captured.out or "no_link" in captured.out.lower()

    def test_min_speed_threshold(self, capsys):
        """Min speed threshold flags slow interfaces."""
        from scripts.baremetal.nic_link_speed import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),  # 10Gb
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        # Set min speed to 25Gb - should fail
        result = run(["--min-speed", "25000"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "below minimum" in captured.out.lower() or "WARNING" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.nic_link_speed import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "interfaces" in data
        assert "summary" in data
        assert "ok" in data["summary"]
        assert "suboptimal" in data["summary"]

    def test_missing_ethtool_exit_2(self, capsys):
        """Missing ethtool returns exit code 2."""
        from scripts.baremetal.nic_link_speed import run

        context = MockContext(tools_available=[])
        output = Output()

        result = run([], output, context)

        assert result == 2
