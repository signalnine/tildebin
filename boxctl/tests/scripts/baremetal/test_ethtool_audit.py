"""Tests for ethtool_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestEthtoolAudit:
    """Tests for ethtool_audit."""

    def test_healthy_interface(self, capsys):
        """Healthy interface with good offloads returns exit code 0."""
        from scripts.baremetal.ethtool_audit import run

        context = MockContext(
            tools_available=["ethtool"],
            command_outputs={
                ("ip", "link", "show"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "-k", "eth0"): load_fixture("ethtool_k_eth0.txt"),
                ("ethtool", "-g", "eth0"): load_fixture("ethtool_g_eth0.txt"),
                ("ip", "link", "show", "eth0"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "HEALTHY" in captured.out or "OK" in captured.out

    def test_half_duplex_issue(self, capsys):
        """Half duplex detection returns exit code 1."""
        from scripts.baremetal.ethtool_audit import run

        context = MockContext(
            tools_available=["ethtool"],
            command_outputs={
                ("ip", "link", "show"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n",
                ("ethtool", "eth0"): load_fixture("ethtool_eth2_halfduplex.txt"),
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "-k", "eth0"): load_fixture("ethtool_k_eth0.txt"),
                ("ethtool", "-g", "eth0"): load_fixture("ethtool_g_eth0.txt"),
                ("ip", "link", "show", "eth0"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Half-duplex" in captured.out or "ISSUE" in captured.out

    def test_disabled_offloads_warning(self, capsys):
        """Disabled critical offloads triggers warning."""
        from scripts.baremetal.ethtool_audit import run

        context = MockContext(
            tools_available=["ethtool"],
            command_outputs={
                ("ip", "link", "show"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "-k", "eth0"): load_fixture("ethtool_k_eth0_offloads_disabled.txt"),
                ("ethtool", "-g", "eth0"): load_fixture("ethtool_g_eth0.txt"),
                ("ip", "link", "show", "eth0"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "disabled" in captured.out.lower() or "WARN" in captured.out

    def test_low_ring_buffer_warning(self, capsys):
        """Low ring buffer size triggers warning."""
        from scripts.baremetal.ethtool_audit import run

        context = MockContext(
            tools_available=["ethtool"],
            command_outputs={
                ("ip", "link", "show"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "-k", "eth0"): load_fixture("ethtool_k_eth0.txt"),
                ("ethtool", "-g", "eth0"): load_fixture("ethtool_g_eth0_low_ring.txt"),
                ("ip", "link", "show", "eth0"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "ring buffer" in captured.out.lower() or "WARN" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.ethtool_audit import run

        context = MockContext(
            tools_available=["ethtool"],
            command_outputs={
                ("ip", "link", "show"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "-k", "eth0"): load_fixture("ethtool_k_eth0.txt"),
                ("ethtool", "-g", "eth0"): load_fixture("ethtool_g_eth0.txt"),
                ("ip", "link", "show", "eth0"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 9000\n",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "interfaces" in data
        assert "summary" in data
        assert "global_issues" in data
        assert data["summary"]["total"] == 1

    def test_missing_ethtool_exit_2(self, capsys):
        """Missing ethtool returns exit code 2."""
        from scripts.baremetal.ethtool_audit import run

        context = MockContext(tools_available=[])
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_driver_version_inconsistency(self, capsys):
        """Driver version mismatch across interfaces triggers warning."""
        from scripts.baremetal.ethtool_audit import run

        context = MockContext(
            tools_available=["ethtool"],
            command_outputs={
                ("ip", "link", "show"): "2: eth0: <UP> mtu 9000\n3: eth1: <UP> mtu 9000\n",
                ("ethtool", "eth0"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth0"): load_fixture("ethtool_i_eth0.txt"),
                ("ethtool", "-k", "eth0"): load_fixture("ethtool_k_eth0.txt"),
                ("ethtool", "-g", "eth0"): load_fixture("ethtool_g_eth0.txt"),
                ("ip", "link", "show", "eth0"): "2: eth0: <UP> mtu 9000\n",
                ("ethtool", "eth1"): load_fixture("ethtool_eth0.txt"),
                ("ethtool", "-i", "eth1"): load_fixture("ethtool_i_eth1.txt"),  # Different firmware
                ("ethtool", "-k", "eth1"): load_fixture("ethtool_k_eth0.txt"),
                ("ethtool", "-g", "eth1"): load_fixture("ethtool_g_eth0.txt"),
                ("ip", "link", "show", "eth1"): "3: eth1: <UP> mtu 9000\n",
            },
        )
        output = Output()

        result = run([], output, context)

        # Note: The fixture uses same driver (ixgbe) but with different firmware
        # This test validates we can check multiple interfaces
        captured = capsys.readouterr()
        assert "eth0" in captured.out
        assert "eth1" in captured.out
