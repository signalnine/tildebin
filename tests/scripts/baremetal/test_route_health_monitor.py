"""Tests for route_health_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestRouteHealthMonitor:
    """Tests for route_health_monitor."""

    def test_missing_ip_command(self):
        """Returns exit code 2 when ip command not available."""
        from scripts.baremetal.route_health_monitor import run

        ctx = MockContext(tools_available=[])
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert any("ip" in e.lower() for e in output.errors)

    def test_healthy_routing(self, capsys):
        """Returns 0 when routing is healthy."""
        from scripts.baremetal.route_health_monitor import run

        route_output = load_fixture("ip_route_healthy.txt")
        link_output = load_fixture("ip_link_eth0_up.txt")
        ping_output = load_fixture("ping_success.txt")

        ctx = MockContext(
            tools_available=["ip", "ping"],
            command_outputs={
                ("ip", "-4", "route", "show", "default"): "default via 192.168.1.1 dev eth0 proto static metric 100",
                ("ip", "-6", "route", "show", "default"): "",
                ("ip", "link", "show", "eth0"): link_output,
                ("ping", "-c", "3", "-W", "2", "192.168.1.1"): ping_output,
            }
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data.get("healthy") is True

    def test_no_default_route_critical(self, capsys):
        """Detects missing default route as critical issue."""
        from scripts.baremetal.route_health_monitor import run

        ctx = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-4", "route", "show", "default"): "",
                ("ip", "-6", "route", "show", "default"): "",
            }
        )
        output = Output()

        exit_code = run(["--no-ping"], output, ctx)

        assert exit_code == 1
        issues = output.data.get("issues", [])
        assert any(i["type"] == "no_default_route" for i in issues)

    def test_gateway_unreachable(self, capsys):
        """Detects unreachable gateway as critical issue."""
        from scripts.baremetal.route_health_monitor import run

        link_output = load_fixture("ip_link_eth0_up.txt")
        ping_timeout = load_fixture("ping_timeout.txt")

        ctx = MockContext(
            tools_available=["ip", "ping"],
            command_outputs={
                ("ip", "-4", "route", "show", "default"): "default via 192.168.1.1 dev eth0",
                ("ip", "-6", "route", "show", "default"): "",
                ("ip", "link", "show", "eth0"): link_output,
                ("ping", "-c", "3", "-W", "2", "192.168.1.1"): ping_timeout,
            }
        )

        # Mock run to return non-zero for ping
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            result = original_run(cmd, **kwargs)
            if cmd[0] == "ping":
                result.returncode = 1
            return result
        ctx.run = mock_run

        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        issues = output.data.get("issues", [])
        assert any(i["type"] == "gateway_unreachable" for i in issues)

    def test_interface_down(self, capsys):
        """Detects route interface that is down."""
        from scripts.baremetal.route_health_monitor import run

        link_down = load_fixture("ip_link_eth0_down.txt")

        ctx = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-4", "route", "show", "default"): "default via 192.168.1.1 dev eth0",
                ("ip", "-6", "route", "show", "default"): "",
                ("ip", "link", "show", "eth0"): link_down,
            }
        )
        output = Output()

        exit_code = run(["--no-ping"], output, ctx)

        assert exit_code == 1
        issues = output.data.get("issues", [])
        assert any(i["type"] == "interface_down" for i in issues)

    def test_multiple_defaults_warning(self, capsys):
        """Detects multiple default routes with same metric."""
        from scripts.baremetal.route_health_monitor import run

        ctx = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-4", "route", "show", "default"): "default via 192.168.1.1 dev eth0 metric 100\ndefault via 192.168.2.1 dev eth1 metric 100",
                ("ip", "-6", "route", "show", "default"): "",
                ("ip", "link", "show", "eth0"): "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP",
                ("ip", "link", "show", "eth1"): "3: eth1: <BROADCAST,MULTICAST,UP> mtu 1500 state UP",
            }
        )
        output = Output()

        exit_code = run(["--no-ping"], output, ctx)

        # Should return 0 (warnings don't cause failure) or 1 depending on implementation
        warnings = output.data.get("warnings", [])
        assert any(w["type"] == "multiple_default_routes" for w in warnings)

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.route_health_monitor import run

        ctx = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-4", "route", "show", "default"): "default via 192.168.1.1 dev eth0",
                ("ip", "-6", "route", "show", "default"): "",
                ("ip", "link", "show", "eth0"): "2: eth0: state UP",
            }
        )
        output = Output()

        exit_code = run(["--format", "json", "--no-ping"], output, ctx)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "default_routes" in data
        assert "interface_status" in data
        assert "issues" in data
        assert "healthy" in data

    def test_no_ping_option(self, capsys):
        """--no-ping skips gateway reachability checks."""
        from scripts.baremetal.route_health_monitor import run

        ctx = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-4", "route", "show", "default"): "default via 192.168.1.1 dev eth0",
                ("ip", "-6", "route", "show", "default"): "",
                ("ip", "link", "show", "eth0"): "2: eth0: state UP",
            }
        )
        output = Output()

        exit_code = run(["--no-ping"], output, ctx)

        assert exit_code == 0
        assert len(output.data.get("gateway_status", {})) == 0
