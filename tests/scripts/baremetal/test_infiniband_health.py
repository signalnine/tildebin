"""Tests for infiniband_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


class TestInfinibandHealth:
    """Tests for infiniband_health script."""

    def test_missing_ib_sysfs_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/class/infiniband not present."""
        from scripts.baremetal import infiniband_health

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = infiniband_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_devices_returns_error(self, mock_context):
        """Returns exit code 2 when no IB devices found."""
        from scripts.baremetal import infiniband_health

        ctx = mock_context(
            file_contents={
                "/sys/class/infiniband": "",  # Directory exists but empty
            }
        )
        output = Output()

        exit_code = infiniband_health.run([], output, ctx)

        assert exit_code == 2

    def test_healthy_ib_port_returns_zero(self, mock_context, fixtures_dir):
        """Returns 0 when IB port is healthy."""
        from scripts.baremetal import infiniband_health

        state = (fixtures_dir / "storage" / "ib_port_state_active.txt").read_text()
        phys_state = (fixtures_dir / "storage" / "ib_phys_state_linkup.txt").read_text()
        rate = (fixtures_dir / "storage" / "ib_port_rate.txt").read_text()
        lid = (fixtures_dir / "storage" / "ib_port_lid.txt").read_text()
        node_type = (fixtures_dir / "storage" / "ib_node_type.txt").read_text()
        fw_ver = (fixtures_dir / "storage" / "ib_fw_ver.txt").read_text()
        counter_zero = (fixtures_dir / "storage" / "ib_counter_zero.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/infiniband": "",
                "/sys/class/infiniband/mlx5_0": "",
                "/sys/class/infiniband/mlx5_0/node_type": node_type,
                "/sys/class/infiniband/mlx5_0/fw_ver": fw_ver,
                "/sys/class/infiniband/mlx5_0/ports": "",
                "/sys/class/infiniband/mlx5_0/ports/1": "",
                "/sys/class/infiniband/mlx5_0/ports/1/state": state,
                "/sys/class/infiniband/mlx5_0/ports/1/phys_state": phys_state,
                "/sys/class/infiniband/mlx5_0/ports/1/rate": rate,
                "/sys/class/infiniband/mlx5_0/ports/1/lid": lid,
                "/sys/class/infiniband/mlx5_0/ports/1/sm_lid": lid,
                "/sys/class/infiniband/mlx5_0/ports/1/counters": "",
                "/sys/class/infiniband/mlx5_0/ports/1/counters/symbol_error": counter_zero,
                "/sys/class/infiniband/mlx5_0/ports/1/counters/link_error_recovery": counter_zero,
            }
        )
        output = Output()

        exit_code = infiniband_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["ports"]) == 1
        assert len(output.data["issues"]) == 0

    def test_port_down_returns_one(self, mock_context, fixtures_dir):
        """Returns 1 when IB port is down."""
        from scripts.baremetal import infiniband_health

        state_down = (fixtures_dir / "storage" / "ib_port_state_down.txt").read_text()
        counter_zero = (fixtures_dir / "storage" / "ib_counter_zero.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/infiniband": "",
                "/sys/class/infiniband/mlx5_0": "",
                "/sys/class/infiniband/mlx5_0/ports": "",
                "/sys/class/infiniband/mlx5_0/ports/1": "",
                "/sys/class/infiniband/mlx5_0/ports/1/state": state_down,
                "/sys/class/infiniband/mlx5_0/ports/1/counters": "",
                "/sys/class/infiniband/mlx5_0/ports/1/counters/symbol_error": counter_zero,
            }
        )
        output = Output()

        exit_code = infiniband_health.run([], output, ctx)

        assert exit_code == 1
        assert any("port_not_active" in i["type"] for i in output.data["issues"])

    def test_error_counters_create_issues(self, mock_context, fixtures_dir):
        """Returns 1 when IB error counters are non-zero."""
        from scripts.baremetal import infiniband_health

        state = (fixtures_dir / "storage" / "ib_port_state_active.txt").read_text()
        lid = (fixtures_dir / "storage" / "ib_port_lid.txt").read_text()
        counter_zero = (fixtures_dir / "storage" / "ib_counter_zero.txt").read_text()
        counter_errors = (fixtures_dir / "storage" / "ib_counter_errors.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/infiniband": "",
                "/sys/class/infiniband/mlx5_0": "",
                "/sys/class/infiniband/mlx5_0/ports": "",
                "/sys/class/infiniband/mlx5_0/ports/1": "",
                "/sys/class/infiniband/mlx5_0/ports/1/state": state,
                "/sys/class/infiniband/mlx5_0/ports/1/lid": lid,
                "/sys/class/infiniband/mlx5_0/ports/1/sm_lid": lid,
                "/sys/class/infiniband/mlx5_0/ports/1/counters": "",
                "/sys/class/infiniband/mlx5_0/ports/1/counters/symbol_error": counter_errors,
                "/sys/class/infiniband/mlx5_0/ports/1/counters/link_error_recovery": counter_zero,
            }
        )
        output = Output()

        exit_code = infiniband_health.run([], output, ctx)

        assert exit_code == 1
        assert any("symbol_error" in i.get("counter", "") for i in output.data["issues"])

    def test_no_lid_creates_warning(self, mock_context, fixtures_dir):
        """Creates warning when port is active but has no LID."""
        from scripts.baremetal import infiniband_health

        state = (fixtures_dir / "storage" / "ib_port_state_active.txt").read_text()
        lid_zero = (fixtures_dir / "storage" / "ib_port_lid_zero.txt").read_text()
        counter_zero = (fixtures_dir / "storage" / "ib_counter_zero.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/infiniband": "",
                "/sys/class/infiniband/mlx5_0": "",
                "/sys/class/infiniband/mlx5_0/ports": "",
                "/sys/class/infiniband/mlx5_0/ports/1": "",
                "/sys/class/infiniband/mlx5_0/ports/1/state": state,
                "/sys/class/infiniband/mlx5_0/ports/1/lid": lid_zero,
                "/sys/class/infiniband/mlx5_0/ports/1/sm_lid": lid_zero,
                "/sys/class/infiniband/mlx5_0/ports/1/counters": "",
                "/sys/class/infiniband/mlx5_0/ports/1/counters/symbol_error": counter_zero,
            }
        )
        output = Output()

        exit_code = infiniband_health.run([], output, ctx)

        assert exit_code == 1
        assert any("no_lid" in i["type"] for i in output.data["issues"])

    def test_verbose_includes_counters(self, mock_context, fixtures_dir):
        """Verbose mode includes error counters in output."""
        from scripts.baremetal import infiniband_health

        state = (fixtures_dir / "storage" / "ib_port_state_active.txt").read_text()
        lid = (fixtures_dir / "storage" / "ib_port_lid.txt").read_text()
        fw_ver = (fixtures_dir / "storage" / "ib_fw_ver.txt").read_text()
        counter_zero = (fixtures_dir / "storage" / "ib_counter_zero.txt").read_text()

        ctx = mock_context(
            file_contents={
                "/sys/class/infiniband": "",
                "/sys/class/infiniband/mlx5_0": "",
                "/sys/class/infiniband/mlx5_0/fw_ver": fw_ver,
                "/sys/class/infiniband/mlx5_0/ports": "",
                "/sys/class/infiniband/mlx5_0/ports/1": "",
                "/sys/class/infiniband/mlx5_0/ports/1/state": state,
                "/sys/class/infiniband/mlx5_0/ports/1/lid": lid,
                "/sys/class/infiniband/mlx5_0/ports/1/sm_lid": lid,
                "/sys/class/infiniband/mlx5_0/ports/1/counters": "",
                "/sys/class/infiniband/mlx5_0/ports/1/counters/symbol_error": counter_zero,
            }
        )
        output = Output()

        exit_code = infiniband_health.run(["-v"], output, ctx)

        assert exit_code == 0
        assert "counters" in output.data["ports"][0]
        assert "fw_ver" in output.data["ports"][0]
