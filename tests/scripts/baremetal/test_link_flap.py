"""Tests for link_flap script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestLinkFlap:
    """Tests for link_flap."""

    def test_stable_interface(self, capsys):
        """Stable interface with low carrier changes returns exit code 0."""
        from scripts.baremetal.link_flap import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",  # Directory exists
                "/sys/class/net/eth0/carrier": "1\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/carrier_changes": "2\n",
                "/sys/class/net/eth0/carrier_up_count": "1\n",
                "/sys/class/net/eth0/carrier_down_count": "1\n",
                "/sys/class/net/eth0/speed": "10000\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "STABLE" in captured.out or "No link flapping" in captured.out

    def test_flapping_interface(self, capsys):
        """Flapping interface with high carrier changes returns exit code 1."""
        from scripts.baremetal.link_flap import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/carrier": "1\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/carrier_changes": "150\n",
                "/sys/class/net/eth0/carrier_up_count": "75\n",
                "/sys/class/net/eth0/carrier_down_count": "75\n",
                "/sys/class/net/eth0/speed": "10000\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "FLAPPING" in captured.out or "flapping" in captured.out.lower()

    def test_custom_threshold(self, capsys):
        """Custom threshold affects detection."""
        from scripts.baremetal.link_flap import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/carrier": "1\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/carrier_changes": "5\n",
                "/sys/class/net/eth0/carrier_up_count": "3\n",
                "/sys/class/net/eth0/carrier_down_count": "2\n",
                "/sys/class/net/eth0/speed": "1000\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        # Default threshold is 10, so 5 changes should be OK
        result = run([], output, context)
        assert result == 0

        # With threshold 3, 5 changes should trigger flapping
        result = run(["--threshold", "3"], output, context)
        assert result == 1

    def test_interface_down(self, capsys):
        """Interface that is down is still reported."""
        from scripts.baremetal.link_flap import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/carrier": "0\n",
                "/sys/class/net/eth0/operstate": "down\n",
                "/sys/class/net/eth0/carrier_changes": "2\n",
                "/sys/class/net/eth0/carrier_up_count": "1\n",
                "/sys/class/net/eth0/carrier_down_count": "1\n",
                "/sys/class/net/eth0/speed": "-1\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "eth0" in captured.out
        assert "DOWN" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.link_flap import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/carrier": "1\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/carrier_changes": "2\n",
                "/sys/class/net/eth0/carrier_up_count": "1\n",
                "/sys/class/net/eth0/carrier_down_count": "1\n",
                "/sys/class/net/eth0/speed": "10000\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "interfaces" in data
        assert "summary" in data
        assert "has_flapping" in data
        assert data["interfaces"][0]["interface"] == "eth0"

    def test_table_output(self, capsys):
        """Table output shows correct columns."""
        from scripts.baremetal.link_flap import run

        context = MockContext(
            file_contents={
                "/sys/class/net": "",
                "/sys/class/net/eth0/carrier": "1\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/carrier_changes": "2\n",
                "/sys/class/net/eth0/carrier_up_count": "1\n",
                "/sys/class/net/eth0/carrier_down_count": "1\n",
                "/sys/class/net/eth0/speed": "10000\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/sys/class/net/eth0"]

        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Interface" in captured.out
        assert "State" in captured.out
        assert "eth0" in captured.out

    def test_missing_sysfs_exit_2(self, capsys):
        """Missing /sys/class/net returns exit code 2."""
        from scripts.baremetal.link_flap import run

        context = MockContext(file_contents={})
        context.glob = lambda pattern, root=".": []

        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_specific_interface(self, capsys):
        """Specific interface flag works correctly."""
        from scripts.baremetal.link_flap import run

        context = MockContext(
            file_contents={
                "/sys/class/net/eth0": "",
                "/sys/class/net/eth0/carrier": "1\n",
                "/sys/class/net/eth0/operstate": "up\n",
                "/sys/class/net/eth0/carrier_changes": "2\n",
                "/sys/class/net/eth0/carrier_up_count": "1\n",
                "/sys/class/net/eth0/carrier_down_count": "1\n",
                "/sys/class/net/eth0/speed": "10000\n",
            },
        )

        output = Output()

        result = run(["-I", "eth0"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "eth0" in captured.out
