"""Tests for bridge_health_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestBridgeHealthMonitor:
    """Tests for bridge_health_monitor."""

    def test_missing_sysfs_returns_error(self):
        """Returns exit code 2 when /sys/class/net not accessible."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(file_contents={})
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert any("/sys/class/net" in e for e in output.errors)

    def test_no_bridges_found(self, capsys):
        """Returns 0 when no bridges found."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
            }
        )
        ctx.glob = lambda p, r: ["/sys/class/net/eth0"]  # No bridges
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0

    def test_healthy_bridge(self, capsys):
        """Returns 0 when bridge is healthy."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/br0/bridge": "",  # marks as bridge
                "/sys/class/net/br0/operstate": "up",
                "/sys/class/net/br0/mtu": "1500",
                "/sys/class/net/br0/address": "52:54:00:12:34:56",
                "/sys/class/net/br0/bridge/bridge_id": "8000.525400123456",
                "/sys/class/net/br0/bridge/stp_state": "1",
                "/sys/class/net/br0/bridge/forward_delay": "200",
                "/sys/class/net/br0/bridge/ageing_time": "30000",
                "/sys/class/net/br0/bridge/root_id": "8000.525400123456",
                "/sys/class/net/br0/bridge/root_port": "0",
                "/sys/class/net/br0/bridge/root_path_cost": "0",
                "/sys/class/net/br0/brif/veth0/state": "3",  # forwarding
                "/sys/class/net/br0/brif/veth0/path_cost": "100",
                "/sys/class/net/br0/brif/veth0/priority": "128",
                "/sys/class/net/br0/brif/veth0/hairpin_mode": "0",
                "/sys/class/net/veth0/operstate": "up",
                "/sys/class/net/veth0/mtu": "1500",
                "/sys/class/net/veth0/address": "52:54:00:12:34:57",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/br0", "/sys/class/net/veth0"]
            elif "brif" in root:
                return ["/sys/class/net/br0/brif/veth0"]
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        issues = output.data.get("issues", [])
        assert len([i for i in issues if i["severity"] in ("critical", "warning")]) == 0

    def test_bridge_down_critical(self, capsys):
        """Detects bridge that is down as critical issue."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/br0/bridge": "",
                "/sys/class/net/br0/operstate": "down",
                "/sys/class/net/br0/mtu": "1500",
                "/sys/class/net/br0/address": "52:54:00:12:34:56",
                "/sys/class/net/br0/bridge/bridge_id": "8000.525400123456",
                "/sys/class/net/br0/bridge/stp_state": "0",
                "/sys/class/net/br0/bridge/root_id": "8000.525400123456",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/br0"]
            elif "brif" in root:
                return []
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        issues = output.data.get("issues", [])
        assert any(i["type"] == "BRIDGE_DOWN" for i in issues)
        assert any(i["severity"] == "critical" for i in issues)

    def test_port_disabled_warning(self, capsys):
        """Detects disabled port as warning."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/br0/bridge": "",
                "/sys/class/net/br0/operstate": "up",
                "/sys/class/net/br0/mtu": "1500",
                "/sys/class/net/br0/address": "52:54:00:12:34:56",
                "/sys/class/net/br0/bridge/bridge_id": "8000.525400123456",
                "/sys/class/net/br0/bridge/stp_state": "1",
                "/sys/class/net/br0/bridge/root_id": "8000.525400123456",
                "/sys/class/net/br0/brif/veth0/state": "0",  # disabled
                "/sys/class/net/br0/brif/veth0/path_cost": "100",
                "/sys/class/net/br0/brif/veth0/priority": "128",
                "/sys/class/net/veth0/operstate": "down",
                "/sys/class/net/veth0/mtu": "1500",
                "/sys/class/net/veth0/address": "52:54:00:12:34:57",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/br0", "/sys/class/net/veth0"]
            elif "brif" in root:
                return ["/sys/class/net/br0/brif/veth0"]
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        issues = output.data.get("issues", [])
        assert any(i["type"] == "PORT_DISABLED" for i in issues)

    def test_mtu_mismatch_warning(self, capsys):
        """Detects MTU mismatch between bridge and port."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/br0/bridge": "",
                "/sys/class/net/br0/operstate": "up",
                "/sys/class/net/br0/mtu": "9000",
                "/sys/class/net/br0/address": "52:54:00:12:34:56",
                "/sys/class/net/br0/bridge/bridge_id": "8000.525400123456",
                "/sys/class/net/br0/bridge/stp_state": "0",
                "/sys/class/net/br0/bridge/root_id": "8000.525400123456",
                "/sys/class/net/br0/brif/veth0/state": "3",
                "/sys/class/net/br0/brif/veth0/path_cost": "100",
                "/sys/class/net/br0/brif/veth0/priority": "128",
                "/sys/class/net/veth0/operstate": "up",
                "/sys/class/net/veth0/mtu": "1500",  # lower than bridge
                "/sys/class/net/veth0/address": "52:54:00:12:34:57",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/br0", "/sys/class/net/veth0"]
            elif "brif" in root:
                return ["/sys/class/net/br0/brif/veth0"]
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        issues = output.data.get("issues", [])
        assert any(i["type"] == "BRIDGE_MTU_EXCEEDS_PORT" for i in issues)

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/br0/bridge": "",
                "/sys/class/net/br0/operstate": "up",
                "/sys/class/net/br0/mtu": "1500",
                "/sys/class/net/br0/address": "52:54:00:12:34:56",
                "/sys/class/net/br0/bridge/bridge_id": "8000.525400123456",
                "/sys/class/net/br0/bridge/stp_state": "0",
                "/sys/class/net/br0/bridge/root_id": "8000.525400123456",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/br0"]
            elif "brif" in root:
                return []
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run(["--format", "json", "--ignore-no-ports"], output, ctx)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "status" in data
        assert "bridge_count" in data
        assert "bridges" in data
        assert "issues" in data

    def test_specific_bridge(self, capsys):
        """Can check specific bridge with -b option."""
        from scripts.baremetal.bridge_health_monitor import run

        ctx = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/br0/bridge": "",
                "/sys/class/net/br0/operstate": "up",
                "/sys/class/net/br0/mtu": "1500",
                "/sys/class/net/br0/address": "52:54:00:12:34:56",
                "/sys/class/net/br0/bridge/bridge_id": "8000.525400123456",
                "/sys/class/net/br0/bridge/stp_state": "0",
                "/sys/class/net/br0/bridge/root_id": "8000.525400123456",
            }
        )

        def mock_glob(pattern, root):
            if root == "/sys/class/net":
                return ["/sys/class/net/br0"]
            elif "brif" in root:
                return []
            return []

        ctx.glob = mock_glob
        output = Output()

        exit_code = run(["-b", "br0", "--ignore-no-ports"], output, ctx)

        assert exit_code == 0
        bridges = output.data.get("bridges", [])
        assert len(bridges) == 1
        assert bridges[0]["name"] == "br0"
