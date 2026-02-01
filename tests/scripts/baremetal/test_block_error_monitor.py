"""Tests for block_error_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def sysblock_healthy_stat(fixtures_dir):
    """Load healthy block device stat."""
    return (fixtures_dir / "storage" / "sysblock_healthy_stat.txt").read_text()


@pytest.fixture
def sysblock_high_inflight_stat(fixtures_dir):
    """Load stat with high in-flight I/Os."""
    return (fixtures_dir / "storage" / "sysblock_high_inflight_stat.txt").read_text()


@pytest.fixture
def sysblock_idle_stat(fixtures_dir):
    """Load completely idle device stat."""
    return (fixtures_dir / "storage" / "sysblock_idle_stat.txt").read_text()


@pytest.fixture
def sysblock_model(fixtures_dir):
    """Load device model."""
    return (fixtures_dir / "storage" / "sysblock_model.txt").read_text()


@pytest.fixture
def sysblock_size(fixtures_dir):
    """Load device size."""
    return (fixtures_dir / "storage" / "sysblock_size.txt").read_text()


class TestBlockErrorMonitor:
    """Tests for block_error_monitor script."""

    def test_no_sysblock_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/block not found."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={},  # No /sys/block
        )
        output = Output()

        exit_code = block_error_monitor.run([], output, ctx)

        assert exit_code == 2
        assert any("/sys/block" in e for e in output.errors)

    def test_no_devices_returns_error(self, mock_context):
        """Returns exit code 2 when no devices found."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={"/sys/block": ""},
            command_outputs={
                ("ls", "-1", "/sys/block"): "",
            }
        )
        output = Output()

        exit_code = block_error_monitor.run([], output, ctx)

        assert exit_code == 2

    def test_healthy_device(
        self,
        mock_context,
        sysblock_healthy_stat,
        sysblock_model,
        sysblock_size,
    ):
        """Returns 0 when device is healthy."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/block": "sda",
                "/sys/block/sda/stat": sysblock_healthy_stat,
                "/sys/block/sda/device/model": sysblock_model,
                "/sys/block/sda/size": sysblock_size,
            },
            command_outputs={
                ("ls", "-1", "/sys/block"): "sda\n",
            }
        )
        output = Output()

        exit_code = block_error_monitor.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["status"] == "healthy"

    def test_high_inflight_warning(
        self,
        mock_context,
        sysblock_high_inflight_stat,
        sysblock_model,
        sysblock_size,
    ):
        """Returns 1 when device has high in-flight I/Os."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/block": "sda",
                "/sys/block/sda/stat": sysblock_high_inflight_stat,
                "/sys/block/sda/device/model": sysblock_model,
                "/sys/block/sda/size": sysblock_size,
            },
            command_outputs={
                ("ls", "-1", "/sys/block"): "sda\n",
            }
        )
        output = Output()

        exit_code = block_error_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["devices"][0]["status"] == "warning"
        assert any("in-flight" in i.lower() for i in output.data["devices"][0]["issues"])

    def test_idle_device_warning(
        self,
        mock_context,
        sysblock_idle_stat,
        sysblock_model,
        sysblock_size,
    ):
        """Returns 1 when device has no I/O activity."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/block": "sda",
                "/sys/block/sda/stat": sysblock_idle_stat,
                "/sys/block/sda/device/model": sysblock_model,
                "/sys/block/sda/size": sysblock_size,
            },
            command_outputs={
                ("ls", "-1", "/sys/block"): "sda\n",
            }
        )
        output = Output()

        exit_code = block_error_monitor.run([], output, ctx)

        assert exit_code == 1
        assert any("no i/o" in i.lower() for i in output.data["devices"][0]["issues"])

    def test_specific_device(
        self,
        mock_context,
        sysblock_healthy_stat,
        sysblock_model,
        sysblock_size,
    ):
        """Can check specific devices."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/block": "sda\nsdb",
                "/sys/block/sda/stat": sysblock_healthy_stat,
                "/sys/block/sda/device/model": sysblock_model,
                "/sys/block/sda/size": sysblock_size,
            },
        )
        output = Output()

        exit_code = block_error_monitor.run(["sda"], output, ctx)

        assert exit_code == 0
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["device"] == "sda"

    def test_verbose_includes_stats(
        self,
        mock_context,
        sysblock_healthy_stat,
        sysblock_model,
        sysblock_size,
    ):
        """--verbose includes detailed stats."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/block": "sda",
                "/sys/block/sda/stat": sysblock_healthy_stat,
                "/sys/block/sda/device/model": sysblock_model,
                "/sys/block/sda/size": sysblock_size,
            },
            command_outputs={
                ("ls", "-1", "/sys/block"): "sda\n",
            }
        )
        output = Output()

        exit_code = block_error_monitor.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "stats" in output.data["devices"][0]
        assert "read_ios" in output.data["devices"][0]["stats"]

    def test_warn_only_filters_healthy(
        self,
        mock_context,
        sysblock_healthy_stat,
        sysblock_model,
        sysblock_size,
    ):
        """--warn-only only shows devices with issues."""
        from scripts.baremetal import block_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/block": "sda",
                "/sys/block/sda/stat": sysblock_healthy_stat,
                "/sys/block/sda/device/model": sysblock_model,
                "/sys/block/sda/size": sysblock_size,
            },
            command_outputs={
                ("ls", "-1", "/sys/block"): "sda\n",
            }
        )
        output = Output()

        exit_code = block_error_monitor.run(["--warn-only"], output, ctx)

        assert exit_code == 0
        assert len(output.data["devices"]) == 0
