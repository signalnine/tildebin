"""Tests for xdp_audit script."""

import json
import pytest

from boxctl.core.output import Output


class TestXdpAudit:
    """Tests for xdp_audit script."""

    def test_ip_missing(self, mock_context):
        """Returns exit code 2 when ip tool not available."""
        from scripts.baremetal.xdp_audit import run

        ctx = mock_context(tools_available=[], file_contents={})
        output = Output()

        assert run([], output, ctx) == 2

    def test_no_xdp(self, mock_context):
        """Returns 0 when no interfaces have XDP programs."""
        from scripts.baremetal.xdp_audit import run

        ip_output = json.dumps([
            {"ifname": "eth0", "link_type": "ether"},
            {"ifname": "lo", "link_type": "loopback"},
        ])
        ctx = mock_context(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-j", "link", "show"): ip_output,
            },
        )
        output = Output()

        assert run([], output, ctx) == 0
        assert output.data["stats"]["xdp_attached"] == 0

    def test_native_xdp(self, mock_context):
        """Returns 0 when XDP is in native mode (healthy)."""
        from scripts.baremetal.xdp_audit import run

        ip_output = json.dumps([
            {
                "ifname": "eth0",
                "link_type": "ether",
                "xdp": {"mode": 1, "prog": {"id": 42, "tag": "abc123", "jited": 1}},
            },
        ])
        ctx = mock_context(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-j", "link", "show"): ip_output,
            },
        )
        output = Output()

        assert run([], output, ctx) == 0
        assert output.data["stats"]["native"] == 1
        assert output.data["stats"]["generic"] == 0

    def test_generic_xdp(self, mock_context):
        """Returns 1 when XDP is in generic/SKB mode (warning)."""
        from scripts.baremetal.xdp_audit import run

        ip_output = json.dumps([
            {
                "ifname": "eth0",
                "link_type": "ether",
                "xdp": {"mode": 2, "prog": {"id": 43, "tag": "def456", "jited": 0}},
            },
        ])
        ctx = mock_context(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-j", "link", "show"): ip_output,
            },
        )
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i["severity"] == "warning" for i in output.data["issues"])

    def test_json_output(self, mock_context):
        """JSON output has expected fields."""
        from scripts.baremetal.xdp_audit import run

        ip_output = json.dumps([
            {"ifname": "eth0", "link_type": "ether"},
        ])
        ctx = mock_context(
            tools_available=["ip"],
            command_outputs={
                ("ip", "-j", "link", "show"): ip_output,
            },
        )
        output = Output()

        run(["--format", "json"], output, ctx)

        assert "xdp_interfaces" in output.data
        assert "stats" in output.data
        assert "issues" in output.data
