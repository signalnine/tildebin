"""Tests for fc_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


class TestFcHealth:
    """Tests for fc_health script."""

    def test_missing_fc_sysfs_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/class/fc_host not present."""
        from scripts.baremetal import fc_health

        ctx = mock_context(
            file_contents={}
        )
        output = Output()

        exit_code = fc_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_hosts_returns_error(self, mock_context):
        """Returns exit code 2 when no FC HBAs found."""
        from scripts.baremetal import fc_health

        ctx = mock_context(
            file_contents={
                "/sys/class/fc_host": "",  # Directory exists but empty
            }
        )
        output = Output()

        exit_code = fc_health.run([], output, ctx)

        assert exit_code == 2

    def test_healthy_fc_host_returns_zero(self, mock_context, fixtures_dir):
        """Returns 0 when FC host is healthy."""
        from scripts.baremetal import fc_health

        port_state = (fixtures_dir / "storage" / "fc_host_online.txt").read_text()
        speed = (fixtures_dir / "storage" / "fc_host_speed.txt").read_text()
        port_name = (fixtures_dir / "storage" / "fc_port_name.txt").read_text()
        node_name = (fixtures_dir / "storage" / "fc_node_name.txt").read_text()
        fabric_name = (fixtures_dir / "storage" / "fc_fabric_name.txt").read_text()
        stats_zero = (fixtures_dir / "storage" / "fc_stats_healthy.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/fc_host": "",
                "/sys/class/fc_host/host0": "",
                "/sys/class/fc_host/host0/port_state": port_state,
                "/sys/class/fc_host/host0/speed": speed,
                "/sys/class/fc_host/host0/port_name": port_name,
                "/sys/class/fc_host/host0/node_name": node_name,
                "/sys/class/fc_host/host0/fabric_name": fabric_name,
                "/sys/class/fc_host/host0/statistics": "",
                "/sys/class/fc_host/host0/statistics/invalid_crc_count": stats_zero,
                "/sys/class/fc_host/host0/statistics/link_failure_count": stats_zero,
                "/sys/class/fc_host/host0/statistics/loss_of_signal_count": stats_zero,
                "/sys/class/fc_host/host0/statistics/loss_of_sync_count": stats_zero,
                "/sys/class/fc_host/host0/statistics/error_frames": stats_zero,
            }
        )
        output = Output()

        exit_code = fc_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["hosts"]) == 1
        assert len(output.data["issues"]) == 0

    def test_linkdown_returns_one(self, mock_context, fixtures_dir):
        """Returns 1 when FC port is linkdown."""
        from scripts.baremetal import fc_health

        port_state = (fixtures_dir / "storage" / "fc_host_linkdown.txt").read_text()
        stats_zero = (fixtures_dir / "storage" / "fc_stats_healthy.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/fc_host": "",
                "/sys/class/fc_host/host0": "",
                "/sys/class/fc_host/host0/port_state": port_state,
                "/sys/class/fc_host/host0/statistics": "",
                "/sys/class/fc_host/host0/statistics/invalid_crc_count": stats_zero,
            }
        )
        output = Output()

        exit_code = fc_health.run([], output, ctx)

        assert exit_code == 1
        assert any("linkdown" in i["message"].lower() or "port_not_online" in i["type"]
                   for i in output.data["issues"])

    def test_error_counters_create_issues(self, mock_context, fixtures_dir):
        """Returns 1 when FC error counters are non-zero."""
        from scripts.baremetal import fc_health

        port_state = (fixtures_dir / "storage" / "fc_host_online.txt").read_text()
        fabric_name = (fixtures_dir / "storage" / "fc_fabric_name.txt").read_text()
        stats_zero = (fixtures_dir / "storage" / "fc_stats_healthy.txt").read_text()
        stats_errors = (fixtures_dir / "storage" / "fc_stats_errors.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/fc_host": "",
                "/sys/class/fc_host/host0": "",
                "/sys/class/fc_host/host0/port_state": port_state,
                "/sys/class/fc_host/host0/fabric_name": fabric_name,
                "/sys/class/fc_host/host0/statistics": "",
                "/sys/class/fc_host/host0/statistics/invalid_crc_count": stats_errors,
                "/sys/class/fc_host/host0/statistics/link_failure_count": stats_zero,
                "/sys/class/fc_host/host0/statistics/loss_of_signal_count": stats_zero,
            }
        )
        output = Output()

        exit_code = fc_health.run([], output, ctx)

        assert exit_code == 1
        assert any("invalid_crc_count" in i.get("counter", "") for i in output.data["issues"])

    def test_no_fabric_creates_warning(self, mock_context, fixtures_dir):
        """Creates warning when port is online but not connected to fabric."""
        from scripts.baremetal import fc_health

        port_state = (fixtures_dir / "storage" / "fc_host_online.txt").read_text()
        stats_zero = (fixtures_dir / "storage" / "fc_stats_healthy.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/fc_host": "",
                "/sys/class/fc_host/host0": "",
                "/sys/class/fc_host/host0/port_state": port_state,
                "/sys/class/fc_host/host0/fabric_name": "0x0\n",
                "/sys/class/fc_host/host0/statistics": "",
                "/sys/class/fc_host/host0/statistics/invalid_crc_count": stats_zero,
            }
        )
        output = Output()

        exit_code = fc_health.run([], output, ctx)

        assert exit_code == 1
        assert any("no_fabric" in i["type"] for i in output.data["issues"])

    def test_verbose_includes_statistics(self, mock_context, fixtures_dir):
        """Verbose mode includes statistics in output."""
        from scripts.baremetal import fc_health

        port_state = (fixtures_dir / "storage" / "fc_host_online.txt").read_text()
        speed = (fixtures_dir / "storage" / "fc_host_speed.txt").read_text()
        fabric_name = (fixtures_dir / "storage" / "fc_fabric_name.txt").read_text()
        stats_zero = (fixtures_dir / "storage" / "fc_stats_healthy.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/fc_host": "",
                "/sys/class/fc_host/host0": "",
                "/sys/class/fc_host/host0/port_state": port_state,
                "/sys/class/fc_host/host0/speed": speed,
                "/sys/class/fc_host/host0/fabric_name": fabric_name,
                "/sys/class/fc_host/host0/statistics": "",
                "/sys/class/fc_host/host0/statistics/invalid_crc_count": stats_zero,
            }
        )
        output = Output()

        exit_code = fc_health.run(["-v"], output, ctx)

        assert exit_code == 0
        assert "statistics" in output.data["hosts"][0]
