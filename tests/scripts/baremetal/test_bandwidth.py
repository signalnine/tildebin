"""Tests for bandwidth script."""

import pytest
from unittest.mock import patch

from boxctl.core.output import Output


NET_DEV_SAMPLE1 = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000000   10000    0    0    0     0          0         0  1000000   10000    0    0    0     0       0          0
  eth0: 5000000   50000    0    0    0     0          0         0  3000000   30000    0    0    0     0       0          0
  eth1: 2000000   20000    0    0    0     0          0         0  1000000   10000    0    0    0     0       0          0
"""

NET_DEV_SAMPLE2 = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1001000   10010    0    0    0     0          0         0  1001000   10010    0    0    0     0       0          0
  eth0: 6000000   51000    0    0    0     0          0         0  4000000   31000    0    0    0     0       0          0
  eth1: 2100000   20100    0    0    0     0          0         0  1050000   10050    0    0    0     0       0          0
"""


class TestBandwidth:
    """Tests for bandwidth script."""

    def test_missing_proc_net_dev(self, mock_context):
        """Returns exit code 2 when /proc/net/dev not available."""
        from scripts.baremetal import bandwidth

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = bandwidth.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    @patch('time.sleep')
    def test_normal_bandwidth(self, mock_sleep, mock_context):
        """Returns 0 when bandwidth is within thresholds."""
        from scripts.baremetal import bandwidth

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/net/dev": NET_DEV_SAMPLE1,
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/speed": "1000",
                "/sys/class/net/eth1/operstate": "up",
                "/sys/class/net/eth1/speed": "1000",
            }
        )

        # Override read_file to return different samples
        call_count = [0]
        original_read = ctx.read_file
        def mock_read(path):
            if path == "/proc/net/dev":
                call_count[0] += 1
                if call_count[0] == 1:
                    return NET_DEV_SAMPLE1
                return NET_DEV_SAMPLE2
            return original_read(path)
        ctx.read_file = mock_read

        output = Output()

        exit_code = bandwidth.run(["--interval", "1"], output, ctx)

        assert exit_code == 0
        assert "interfaces" in output.data
        assert len(output.data["interfaces"]) >= 2  # eth0 and eth1, not lo
        # Verify loopback is excluded
        iface_names = [i["interface"] for i in output.data["interfaces"]]
        assert "lo" not in iface_names

    @patch('time.sleep')
    def test_single_interface(self, mock_sleep, mock_context):
        """Can filter to specific interface."""
        from scripts.baremetal import bandwidth

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/net/dev": NET_DEV_SAMPLE1,
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/speed": "1000",
            }
        )

        # Override read_file for sampling
        call_count = [0]
        original_read = ctx.read_file
        def mock_read(path):
            if path == "/proc/net/dev":
                call_count[0] += 1
                if call_count[0] == 1:
                    return NET_DEV_SAMPLE1
                return NET_DEV_SAMPLE2
            return original_read(path)
        ctx.read_file = mock_read

        output = Output()

        exit_code = bandwidth.run(["--interface", "eth0"], output, ctx)

        assert exit_code == 0
        assert len(output.data["interfaces"]) == 1
        assert output.data["interfaces"][0]["interface"] == "eth0"

    @patch('time.sleep')
    def test_interface_not_found(self, mock_sleep, mock_context):
        """Returns 2 when specified interface not found."""
        from scripts.baremetal import bandwidth

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/net/dev": NET_DEV_SAMPLE1,
            }
        )

        call_count = [0]
        original_read = ctx.read_file
        def mock_read(path):
            if path == "/proc/net/dev":
                call_count[0] += 1
                if call_count[0] == 1:
                    return NET_DEV_SAMPLE1
                return NET_DEV_SAMPLE2
            return original_read(path)
        ctx.read_file = mock_read

        output = Output()

        exit_code = bandwidth.run(["--interface", "nonexistent"], output, ctx)

        assert exit_code == 2
        assert any("not found" in e.lower() for e in output.errors)

    def test_invalid_interval(self, mock_context):
        """Returns 2 for invalid interval."""
        from scripts.baremetal import bandwidth

        ctx = mock_context(tools_available=[], file_contents={})
        output = Output()

        exit_code = bandwidth.run(["--interval", "0"], output, ctx)

        assert exit_code == 2
        assert any("interval" in e.lower() for e in output.errors)

    def test_invalid_thresholds(self, mock_context):
        """Returns 2 when warn >= crit."""
        from scripts.baremetal import bandwidth

        ctx = mock_context(tools_available=[], file_contents={})
        output = Output()

        exit_code = bandwidth.run(["--warn", "90", "--crit", "80"], output, ctx)

        assert exit_code == 2
        assert any("threshold" in e.lower() for e in output.errors)

    @patch('time.sleep')
    def test_exclude_down_interfaces(self, mock_sleep, mock_context):
        """--exclude-down filters out down interfaces."""
        from scripts.baremetal import bandwidth

        ctx = mock_context(
            tools_available=[],
            file_contents={
                "/proc/net/dev": NET_DEV_SAMPLE1,
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/speed": "1000",
                "/sys/class/net/eth1/operstate": "down",
                "/sys/class/net/eth1/speed": "1000",
            }
        )

        call_count = [0]
        original_read = ctx.read_file
        def mock_read(path):
            if path == "/proc/net/dev":
                call_count[0] += 1
                if call_count[0] == 1:
                    return NET_DEV_SAMPLE1
                return NET_DEV_SAMPLE2
            return original_read(path)
        ctx.read_file = mock_read

        output = Output()

        exit_code = bandwidth.run(["--exclude-down"], output, ctx)

        assert exit_code == 0
        # Should only have eth0 (up), not eth1 (down)
        iface_names = [i["interface"] for i in output.data["interfaces"]]
        assert "eth0" in iface_names
        assert "eth1" not in iface_names
