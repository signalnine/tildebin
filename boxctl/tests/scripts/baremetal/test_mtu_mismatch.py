"""Tests for mtu_mismatch script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestMtuMismatch:
    """Tests for mtu_mismatch."""

    def test_standard_mtu_ok(self, capsys):
        """Standard MTU (1500) on all interfaces returns exit code 0."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/speed": "1000\n",
            },
        )
        context.glob = lambda pattern, root=".": (
            ["/sys/class/net/eth0"] if root == "/sys/class/net" else []
        )

        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "No MTU" in captured.out

    def test_jumbo_mtu_ok(self, capsys):
        """Jumbo MTU (9000) returns exit code 0."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "9000\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/speed": "10000\n",
            },
        )
        context.glob = lambda pattern, root=".": (
            ["/sys/class/net/eth0"] if root == "/sys/class/net" else []
        )

        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_expected_mtu_mismatch(self, capsys):
        """Expected MTU mismatch returns exit code 1."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/speed": "10000\n",
            },
        )
        context.glob = lambda pattern, root=".": (
            ["/sys/class/net/eth0"] if root == "/sys/class/net" else []
        )

        output = Output()

        # Expect 9000 but got 1500
        result = run(["--expected", "9000"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "does not match expected" in captured.out or "ERROR" in captured.out

    def test_bond_mtu_mismatch(self, capsys):
        """Bond slave MTU mismatch returns exit code 1."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/bond0/mtu": "9000\n",
                "/sys/class/net/bond0/operstate": "up\n",
                "/sys/class/net/bond0/bonding": "",  # Marks as bond
                "/sys/class/net/bond0/bonding/slaves": "eth0 eth1\n",
                "/sys/class/net/eth0/mtu": "9000\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth1/mtu": "1500\n",  # Mismatched!
                "/sys/class/net/eth1/operstate": "up\n",
            },
        )
        context.glob = lambda pattern, root=".": (
            ["/sys/class/net/bond0", "/sys/class/net/eth0", "/sys/class/net/eth1"]
            if root == "/sys/class/net"
            else []
        )

        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "mismatch" in captured.out.lower() or "ERROR" in captured.out

    def test_jumbo_expected_warning(self, capsys):
        """High-speed interface without jumbo frames triggers warning."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/speed": "25000\n",  # 25Gb
            },
        )
        context.glob = lambda pattern, root=".": (
            ["/sys/class/net/eth0"] if root == "/sys/class/net" else []
        )

        output = Output()

        result = run(["--jumbo-expected"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "jumbo" in captured.out.lower() or "WARN" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/speed": "1000\n",
            },
        )
        context.glob = lambda pattern, root=".": (
            ["/sys/class/net/eth0"] if root == "/sys/class/net" else []
        )

        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "interfaces" in data
        assert "summary" in data
        assert "issues" in data
        assert "warnings" in data
        assert data["summary"]["total_interfaces"] == 1

    def test_table_output(self, capsys):
        """Table output shows correct columns."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/mtu": "1500\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/speed": "1000\n",
            },
        )
        context.glob = lambda pattern, root=".": (
            ["/sys/class/net/eth0"] if root == "/sys/class/net" else []
        )

        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Interface" in captured.out
        assert "MTU" in captured.out
        assert "eth0" in captured.out

    def test_missing_sysfs_exit_2(self, capsys):
        """Missing /sys/class/net returns exit code 2."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(file_contents={})

        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_invalid_expected_mtu_exit_2(self, capsys):
        """Invalid expected MTU returns exit code 2."""
        from scripts.baremetal.mtu_mismatch import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
            },
        )

        output = Output()

        result = run(["--expected", "50"], output, context)

        assert result == 2
