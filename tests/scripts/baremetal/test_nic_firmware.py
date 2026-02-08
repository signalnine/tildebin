"""Tests for nic_firmware script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNicFirmware:
    """Tests for nic_firmware."""

    def test_consistent_firmware(self, capsys):
        """Consistent firmware versions return exit code 0."""
        from scripts.baremetal.nic_firmware import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "ixgbe" in captured.out

    def test_firmware_version_inconsistency(self, capsys):
        """Inconsistent firmware versions return exit code 1."""
        from scripts.baremetal.nic_firmware import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
                "/sys/class/net/eth1/device": "",
                "/sys/class/net/eth1/type": "1",
            },
            command_outputs={
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth1"): load_fixture("ethtool_i_eth1.txt"),  # Different firmware
                ("ethtool", "eth1"): load_fixture("ethtool_eth0.txt"),
            },
        )
        context.glob = lambda pattern, root=".": [
            "/sys/class/net/eth0",
            "/sys/class/net/eth1",
        ]

        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert output.data["inconsistencies"]
        assert output.data["summary"]["inconsistency_count"] > 0

    def test_different_drivers_no_issue(self, capsys):
        """Different drivers with different versions is not an inconsistency."""
        from scripts.baremetal.nic_firmware import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
                "/sys/class/net/eth1/device": "",
                "/sys/class/net/eth1/type": "1",
            },
            command_outputs={
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),  # ixgbe
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth1"): load_fixture("ethtool_i_eth2.txt"),  # mlx5_core
                ("ethtool", "eth1"): load_fixture("ethtool_eth0.txt"),
            },
        )
        context.glob = lambda pattern, root=".": [
            "/sys/class/net/eth0",
            "/sys/class/net/eth1",
        ]

        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should show both interfaces without issues
        assert "eth0" in captured.out
        assert "eth1" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.nic_firmware import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "interfaces" in data
        assert "inconsistencies" in data
        assert "summary" in data
        assert data["interfaces"][0]["driver"] == "ixgbe"

    def test_table_output(self, capsys):
        """Table output shows correct columns."""
        from scripts.baremetal.nic_firmware import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={
                "/sys/class/net/eth0/device": "",
                "/sys/class/net/eth0/type": "1",
            },
            command_outputs={
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Interface" in captured.out
        assert "Driver" in captured.out
        assert "eth0" in captured.out

    def test_missing_ethtool_exit_2(self, capsys):
        """Missing ethtool returns exit code 2."""
        from scripts.baremetal.nic_firmware import run

        context = MockContext(tools_available=[])
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_no_interfaces_found(self, capsys):
        """No physical interfaces returns exit code 0."""
        from scripts.baremetal.nic_firmware import run

        context = MockContext(
            tools_available=["ethtool"],
            file_contents={},
        )
        context.glob = lambda pattern, root=".": []

        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No physical" in captured.out or "interfaces" in captured.out.lower()
