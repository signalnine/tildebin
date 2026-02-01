"""Tests for vlan_config_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestVlanConfigAudit:
    """Tests for vlan_config_audit."""

    def test_missing_sysfs_returns_error(self):
        """Returns exit code 2 when /sys/class/net not accessible."""
        from scripts.baremetal.vlan_config_audit import run

        ctx = MockContext(file_contents={})
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert any("/sys/class/net" in e for e in output.errors)

    def test_no_vlans_found(self, capsys):
        """Returns 0 when no VLANs configured."""
        from scripts.baremetal.vlan_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0"]  # No VLANs
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert len(output.data.get("vlans", [])) == 0

    def test_healthy_vlan(self, capsys):
        """Returns 0 when VLAN is healthy."""
        from scripts.baremetal.vlan_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0": "",  # marker for parent exists
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0.100": "",  # marker for interface exists
                "/sys/class/net/eth0.100/flags": "0x1003",
                "/sys/class/net/eth0.100/operstate": "up",
                "/sys/class/net/eth0.100/mtu": "1500",
                "/sys/class/net/eth0.200": "",  # marker for interface exists
                "/sys/class/net/eth0.200/flags": "0x1003",
                "/sys/class/net/eth0.200/operstate": "up",
                "/sys/class/net/eth0.200/mtu": "1500",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0", "/sys/class/net/eth0.100", "/sys/class/net/eth0.200"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        vlans = output.data.get("vlans", [])
        assert all(v["status"] == "ok" for v in vlans)

    def test_parent_down_warning(self, capsys):
        """Detects parent interface that is down."""
        from scripts.baremetal.vlan_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0": "",  # marker for parent exists
                "/sys/class/net/eth0/flags": "0x1002",  # not UP
                "/sys/class/net/eth0/operstate": "down",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0.100": "",  # marker for interface exists
                "/sys/class/net/eth0.100/flags": "0x1002",
                "/sys/class/net/eth0.100/operstate": "down",
                "/sys/class/net/eth0.100/mtu": "1500",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/eth0", "/sys/class/net/eth0.100"]
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        vlans = output.data.get("vlans", [])
        assert len(vlans) == 1
        assert vlans[0]["status"] in ("warning", "error")
        assert any("parent" in issue.lower() or "down" in issue.lower() for issue in vlans[0]["issues"])

    def test_mtu_mismatch_warning(self, capsys):
        """Detects VLAN MTU exceeding parent MTU."""
        from scripts.baremetal.vlan_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0": "",  # marker for parent exists
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0.100": "",  # marker for interface exists
                "/sys/class/net/eth0.100/flags": "0x1003",
                "/sys/class/net/eth0.100/operstate": "up",
                "/sys/class/net/eth0.100/mtu": "9000",  # exceeds parent
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/eth0", "/sys/class/net/eth0.100"]
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        vlans = output.data.get("vlans", [])
        assert any("mtu" in issue.lower() for issue in vlans[0]["issues"])

    def test_orphaned_vlan_error(self, capsys):
        """Detects VLAN with non-existent parent."""
        from scripts.baremetal.vlan_config_audit import run

        vlan_config = "VLAN Dev name    | VLAN ID\neth99.100         | 100  | eth99\n"
        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/proc/net/vlan/config": vlan_config,
                "/sys/class/net/eth99.100/flags": "0x1003",
                "/sys/class/net/eth99.100/operstate": "up",
                "/sys/class/net/eth99.100/mtu": "1500",
                # eth99 does not exist
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth99.100"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        vlans = output.data.get("vlans", [])
        assert vlans[0]["status"] == "error"
        assert any("orphan" in issue.lower() or "not exist" in issue.lower()
                   for issue in vlans[0]["issues"])

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.vlan_config_audit import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0.100/flags": "0x1003",
                "/sys/class/net/eth0.100/operstate": "up",
                "/sys/class/net/eth0.100/mtu": "1500",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/eth0", "/sys/class/net/eth0.100"]
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "vlans" in data
        assert "conflicts" in data
        assert "summary" in data

    def test_vlan_id_conflict(self, capsys):
        """Detects duplicate VLAN IDs on same parent."""
        from scripts.baremetal.vlan_config_audit import run

        # Two different interfaces claim the same VLAN ID on same parent
        vlan_config = """VLAN Dev name    | VLAN ID
eth0.100         | 100  | eth0
vlan100          | 100  | eth0
"""
        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/proc/net/vlan/config": vlan_config,
                "/sys/class/net/eth0/flags": "0x1003",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/mtu": "1500",
                "/sys/class/net/eth0.100/flags": "0x1003",
                "/sys/class/net/eth0.100/operstate": "up",
                "/sys/class/net/eth0.100/mtu": "1500",
                "/sys/class/net/vlan100/flags": "0x1003",
                "/sys/class/net/vlan100/operstate": "up",
                "/sys/class/net/vlan100/mtu": "1500",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0", "/sys/class/net/eth0.100", "/sys/class/net/vlan100"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        conflicts = output.data.get("conflicts", [])
        assert len(conflicts) > 0
        assert conflicts[0]["vlan_id"] == 100
