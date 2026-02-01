"""Tests for arp_table_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestArpTableMonitor:
    """Tests for arp_table_monitor."""

    def test_healthy_arp_table(self, capsys):
        """Healthy ARP table returns exit code 0."""
        from scripts.baremetal.arp_table_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/arp": load_fixture("net_arp_healthy.txt"),
                "/proc/net/route": load_fixture("route_with_gateway.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh1": load_fixture("gc_thresh1.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh2": load_fixture("gc_thresh2.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh3": load_fixture("gc_thresh3.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "healthy" in captured.out.lower() or "no issues" in captured.out.lower()

    def test_incomplete_entries_warning(self, capsys):
        """Incomplete ARP entries return exit code 1."""
        from scripts.baremetal.arp_table_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/arp": load_fixture("net_arp_incomplete.txt"),
                "/proc/net/route": load_fixture("route_with_gateway.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh1": load_fixture("gc_thresh1.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh2": load_fixture("gc_thresh2.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh3": load_fixture("gc_thresh3.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "incomplete" in captured.out.lower()

    def test_duplicate_mac_warning(self, capsys):
        """Duplicate MAC addresses return exit code 1."""
        from scripts.baremetal.arp_table_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/arp": load_fixture("net_arp_duplicate_mac.txt"),
                "/proc/net/route": load_fixture("route_with_gateway.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh1": load_fixture("gc_thresh1.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh2": load_fixture("gc_thresh2.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh3": load_fixture("gc_thresh3.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "MAC" in captured.out or "duplicate" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.arp_table_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/arp": load_fixture("net_arp_healthy.txt"),
                "/proc/net/route": load_fixture("route_with_gateway.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh1": load_fixture("gc_thresh1.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh2": load_fixture("gc_thresh2.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh3": load_fixture("gc_thresh3.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "stats" in data
        assert "limits" in data
        assert "issues" in data
        assert "gateways" in data

    def test_table_output(self, capsys):
        """Table output displays properly."""
        from scripts.baremetal.arp_table_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/arp": load_fixture("net_arp_healthy.txt"),
                "/proc/net/route": load_fixture("route_with_gateway.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh1": load_fixture("gc_thresh1.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh2": load_fixture("gc_thresh2.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh3": load_fixture("gc_thresh3.txt"),
            }
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "METRIC" in captured.out
        assert "VALUE" in captured.out

    def test_missing_proc_net_arp(self, capsys):
        """Missing /proc/net/arp returns exit code 2."""
        from scripts.baremetal.arp_table_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_works_without_route_file(self, capsys):
        """Script works even without /proc/net/route."""
        from scripts.baremetal.arp_table_monitor import run

        context = MockContext(
            file_contents={
                "/proc/net/arp": load_fixture("net_arp_healthy.txt"),
                # No route file - gateways will be empty
                "/proc/sys/net/ipv4/neigh/default/gc_thresh1": load_fixture("gc_thresh1.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh2": load_fixture("gc_thresh2.txt"),
                "/proc/sys/net/ipv4/neigh/default/gc_thresh3": load_fixture("gc_thresh3.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        # Should still work, just no gateway checks
        assert result == 0
