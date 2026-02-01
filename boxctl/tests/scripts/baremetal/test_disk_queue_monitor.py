"""Tests for disk_queue_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "sysfs"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestDiskQueueMonitor:
    """Tests for disk_queue_monitor."""

    def test_no_devices_returns_error(self, mock_context):
        """Returns exit code 2 when no devices found."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={},  # No /sys/block entries
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 2
        assert len(output.errors) > 0

    def test_healthy_queue_depth(self, mock_context):
        """Normal queue depth returns exit code 0."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={
                "/sys/block/sda": "",  # Directory marker
                "/sys/block/sda/device": "",  # Physical device marker
                "/sys/block/sda/stat": load_fixture("block_stat_healthy.txt"),
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/nr_requests": "128",
                "/sys/block/sda/queue/scheduler": "[mq-deadline] none",
                "/sys/block/sda/size": "1000000000",
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert output.data["summary"]["ok"] == 1
        assert output.data["devices"][0]["status"] == "ok"

    def test_warning_queue_depth(self, mock_context):
        """High queue depth returns warning."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={
                "/sys/block/sda": "",
                "/sys/block/sda/device": "",
                "/sys/block/sda/stat": load_fixture("block_stat_warning.txt"),
                "/sys/block/sda/queue/rotational": "1",
                "/sys/block/sda/queue/nr_requests": "128",
                "/sys/block/sda/queue/scheduler": "[cfq]",
                "/sys/block/sda/size": "2000000000",
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["devices"][0]["status"] == "warning"
        assert output.data["devices"][0]["queue_depth"] >= 16

    def test_critical_queue_depth(self, mock_context):
        """Very high queue depth returns critical."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={
                "/sys/block/sda": "",
                "/sys/block/sda/device": "",
                "/sys/block/sda/stat": load_fixture("block_stat_critical.txt"),
                "/sys/block/sda/queue/rotational": "1",
                "/sys/block/sda/queue/nr_requests": "128",
                "/sys/block/sda/queue/scheduler": "[deadline]",
                "/sys/block/sda/size": "4000000000",
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["devices"][0]["status"] == "critical"
        assert output.data["devices"][0]["queue_depth"] >= 32

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds are respected."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={
                "/sys/block/sda": "",
                "/sys/block/sda/device": "",
                "/sys/block/sda/stat": load_fixture("block_stat_warning.txt"),
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/nr_requests": "128",
                "/sys/block/sda/queue/scheduler": "[none]",
                "/sys/block/sda/size": "1000000000",
            },
        )
        output = Output()

        # With very high thresholds, should be OK
        result = run(["--warn", "100", "--crit", "200"], output, ctx)

        assert result == 0
        assert output.data["devices"][0]["status"] == "ok"

    def test_invalid_thresholds(self, mock_context):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={
                "/sys/block/sda": "",
                "/sys/block/sda/device": "",
            },
        )
        output = Output()

        # warn >= crit is invalid
        result = run(["--warn", "50", "--crit", "50"], output, ctx)

        assert result == 2
        assert len(output.errors) > 0

    def test_warn_only_mode(self, mock_context):
        """--warn-only filters to show only problematic devices."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={
                "/sys/block/sda": "",
                "/sys/block/sda/device": "",
                "/sys/block/sda/stat": load_fixture("block_stat_healthy.txt"),
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/nr_requests": "128",
                "/sys/block/sda/queue/scheduler": "[none]",
                "/sys/block/sda/size": "1000000000",
                "/sys/block/sdb": "",
                "/sys/block/sdb/device": "",
                "/sys/block/sdb/stat": load_fixture("block_stat_warning.txt"),
                "/sys/block/sdb/queue/rotational": "1",
                "/sys/block/sdb/queue/nr_requests": "128",
                "/sys/block/sdb/queue/scheduler": "[cfq]",
                "/sys/block/sdb/size": "2000000000",
            },
        )
        output = Output()

        result = run(["--warn-only"], output, ctx)

        assert result == 1
        # Only the warning device should be shown
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["status"] == "warning"

    def test_device_type_detection(self, mock_context):
        """Device type is correctly detected."""
        from scripts.baremetal.disk_queue_monitor import run

        ctx = mock_context(
            file_contents={
                "/sys/block/sda": "",
                "/sys/block/sda/device": "",
                "/sys/block/sda/stat": load_fixture("block_stat_healthy.txt"),
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/nr_requests": "128",
                "/sys/block/sda/queue/scheduler": "[none]",
                "/sys/block/sda/size": "1000000000",
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        # rotational=0 means SSD
        assert output.data["devices"][0]["type"] == "ssd"
