"""Tests for network_config_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestNetworkConfigAudit:
    """Tests for network_config_audit."""

    def test_missing_sysfs_returns_error(self):
        """Returns exit code 2 when /sys/class/net not accessible."""
        from scripts.baremetal.network_config_audit import run

        ctx = MockContext(file_contents={})
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert any("/sys/class/net" in e for e in output.errors)

    def test_healthy_interfaces(self):
        """Returns 0 when all interfaces are healthy."""
        from scripts.baremetal.network_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",  # exists marker
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth1/mtu": "1500",
                "/sys/class/net/eth1/operstate": "up",
                "/sys/class/net/eth1/flags": "0x1003",
                "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "0",
                "/proc/sys/net/ipv6/conf/eth1/disable_ipv6": "0",
            }
        )
        # Mock glob to return interfaces
        ctx.glob = lambda p, r: ["/sys/class/net/eth0", "/sys/class/net/eth1"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert len(output.data.get("findings", [])) == 0

    def test_mtu_mismatch_detected(self, capsys):
        """Detects MTU mismatch between interfaces."""
        from scripts.baremetal.network_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth1/mtu": "9000",
                "/sys/class/net/eth1/operstate": "up",
                "/sys/class/net/eth1/flags": "0x1003",
                "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "0",
                "/proc/sys/net/ipv6/conf/eth1/disable_ipv6": "0",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0", "/sys/class/net/eth1"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        findings = output.data.get("findings", [])
        assert any("mtu" in f["category"].lower() for f in findings)

    def test_ipv6_inconsistency_detected(self, capsys):
        """Detects IPv6 enabled on some interfaces but not others."""
        from scripts.baremetal.network_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth1/mtu": "1500",
                "/sys/class/net/eth1/operstate": "up",
                "/sys/class/net/eth1/flags": "0x1003",
                "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "0",
                "/proc/sys/net/ipv6/conf/eth1/disable_ipv6": "1",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0", "/sys/class/net/eth1"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        findings = output.data.get("findings", [])
        assert any("ipv6" in f["category"].lower() for f in findings)

    def test_promiscuous_mode_warning(self, capsys):
        """Warns when interface is in promiscuous mode."""
        from scripts.baremetal.network_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/flags": "0x1103",  # IFF_PROMISC set
                "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "0",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        findings = output.data.get("findings", [])
        assert any("security" in f["category"].lower() for f in findings)
        assert any("promiscuous" in f["message"].lower() for f in findings)

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.network_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/flags": "0x1003",
                "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "0",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0"]
        output = Output()

        exit_code = run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "findings" in data
        assert "interface_count" in data

    def test_bond_slave_down_error(self, capsys):
        """Detects bond slave that is down."""
        from scripts.baremetal.network_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/bond0/mtu": "1500",
                "/sys/class/net/bond0/operstate": "up",
                "/sys/class/net/bond0/flags": "0x1003",
                "/sys/class/net/bond0/bonding": "",  # marks as bond
                "/sys/class/net/bond0/bonding/mode": "802.3ad 4",
                "/sys/class/net/bond0/bonding/slaves": "eth0 eth1",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth1/mtu": "1500",
                "/sys/class/net/eth1/operstate": "down",
                "/sys/class/net/eth1/flags": "0x1002",
                "/proc/sys/net/ipv6/conf/bond0/disable_ipv6": "0",
                "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "0",
                "/proc/sys/net/ipv6/conf/eth1/disable_ipv6": "0",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/bond0", "/sys/class/net/eth0", "/sys/class/net/eth1"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        findings = output.data.get("findings", [])
        assert any(f["severity"] == "error" for f in findings)
        assert any("eth1" in f["message"] and "down" in f["message"] for f in findings)
