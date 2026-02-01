"""Tests for netns_health_monitor script."""

import json
import subprocess
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNetnsHealthMonitor:
    """Tests for netns_health_monitor."""

    def test_no_namespaces_healthy(self, capsys):
        """No namespaces returns exit code 0."""
        from scripts.baremetal.netns_health_monitor import run

        context = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "netns", "list"): load_fixture("netns_list_empty.txt"),
                ("ip", "-j", "link", "show", "type", "veth"): "[]",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out.lower()

    def test_healthy_namespaces(self, capsys):
        """Healthy namespaces return exit code 0."""
        from scripts.baremetal.netns_health_monitor import run

        context = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "netns", "list"): load_fixture("netns_list_healthy.txt"),
                ("ip", "-j", "link", "show", "type", "veth"): load_fixture(
                    "netns_veth_list.json"
                ),
                (
                    "ip",
                    "netns",
                    "exec",
                    "container1",
                    "ip",
                    "-j",
                    "link",
                    "show",
                ): load_fixture("netns_ip_link_healthy.json"),
                (
                    "ip",
                    "netns",
                    "exec",
                    "container2",
                    "ip",
                    "-j",
                    "link",
                    "show",
                ): load_fixture("netns_ip_link_healthy.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "container1" in captured.out or "OK" in captured.out

    def test_namespace_with_down_interface(self, capsys):
        """Namespace with down interface returns exit code 1."""
        from scripts.baremetal.netns_health_monitor import run

        context = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "netns", "list"): "container1\n",
                ("ip", "-j", "link", "show", "type", "veth"): "[]",
                (
                    "ip",
                    "netns",
                    "exec",
                    "container1",
                    "ip",
                    "-j",
                    "link",
                    "show",
                ): load_fixture("netns_ip_link_down.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Down" in captured.out or "issue" in captured.out.lower()

    def test_dangling_veth(self, capsys):
        """Dangling veth returns exit code 1."""
        from scripts.baremetal.netns_health_monitor import run

        context = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "netns", "list"): "",
                ("ip", "-j", "link", "show", "type", "veth"): load_fixture(
                    "netns_veth_dangling.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Dangling" in captured.out or "veth" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.netns_health_monitor import run

        context = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "netns", "list"): load_fixture("netns_list_healthy.txt"),
                ("ip", "-j", "link", "show", "type", "veth"): "[]",
                (
                    "ip",
                    "netns",
                    "exec",
                    "container1",
                    "ip",
                    "-j",
                    "link",
                    "show",
                ): load_fixture("netns_ip_link_healthy.json"),
                (
                    "ip",
                    "netns",
                    "exec",
                    "container2",
                    "ip",
                    "-j",
                    "link",
                    "show",
                ): load_fixture("netns_ip_link_healthy.json"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "named_namespaces" in data
        assert "dangling_veths" in data
        assert "healthy" in data

    def test_missing_ip_command_exit_2(self, capsys):
        """Missing ip command returns exit code 2."""
        from scripts.baremetal.netns_health_monitor import run

        context = MockContext(tools_available=[])
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_no_output_if_healthy(self, capsys):
        """With --warn-only, no output if healthy."""
        from scripts.baremetal.netns_health_monitor import run

        context = MockContext(
            tools_available=["ip"],
            command_outputs={
                ("ip", "netns", "list"): "",
                ("ip", "-j", "link", "show", "type", "veth"): "[]",
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should have minimal or no output
        assert captured.out == "" or "issue" not in captured.out.lower()
