"""Tests for scsi_error_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


class TestScsiErrorMonitor:
    """Tests for scsi_error_monitor script."""

    def test_missing_scsi_sysfs_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/class/scsi_device not present."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = scsi_error_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_devices_returns_error(self, mock_context):
        """Returns exit code 2 when no SCSI devices found."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/class/scsi_device": "",  # Directory exists but empty
            }
        )
        output = Output()

        exit_code = scsi_error_monitor.run([], output, ctx)

        assert exit_code == 2

    def test_healthy_device_returns_zero(self, mock_context, fixtures_dir):
        """Returns 0 when SCSI device is healthy."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/class/scsi_device": "",
                "/sys/class/scsi_device/0:0:0:0": "",
                "/sys/class/scsi_device/0:0:0:0/device": "",
                "/sys/class/scsi_device/0:0:0:0/device/vendor": "SEAGATE\n",
                "/sys/class/scsi_device/0:0:0:0/device/model": "ST4000NM0035\n",
                "/sys/class/scsi_device/0:0:0:0/device/rev": "0001\n",
                "/sys/class/scsi_device/0:0:0:0/device/type": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/state": "running\n",
                "/sys/class/scsi_device/0:0:0:0/device/iorequest_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/iodone_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/ioerr_cnt": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/iotmo_cnt": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/block": "",
                "/sys/class/scsi_device/0:0:0:0/device/block/sda": "",
            }
        )
        output = Output()

        exit_code = scsi_error_monitor.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["status"] == "healthy"

    def test_io_errors_returns_one(self, mock_context):
        """Returns 1 when SCSI device has I/O errors."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/class/scsi_device": "",
                "/sys/class/scsi_device/0:0:0:0": "",
                "/sys/class/scsi_device/0:0:0:0/device": "",
                "/sys/class/scsi_device/0:0:0:0/device/vendor": "SEAGATE\n",
                "/sys/class/scsi_device/0:0:0:0/device/model": "ST4000NM0035\n",
                "/sys/class/scsi_device/0:0:0:0/device/type": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/state": "running\n",
                "/sys/class/scsi_device/0:0:0:0/device/iorequest_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/iodone_cnt": "999900\n",
                "/sys/class/scsi_device/0:0:0:0/device/ioerr_cnt": "50\n",
                "/sys/class/scsi_device/0:0:0:0/device/iotmo_cnt": "50\n",
            }
        )
        output = Output()

        exit_code = scsi_error_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["devices"][0]["status"] in ("warning", "critical")
        assert any("I/O errors" in i for i in output.data["devices"][0]["issues"])

    def test_io_timeouts_creates_issue(self, mock_context):
        """Creates issue when SCSI device has I/O timeouts."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/class/scsi_device": "",
                "/sys/class/scsi_device/0:0:0:0": "",
                "/sys/class/scsi_device/0:0:0:0/device": "",
                "/sys/class/scsi_device/0:0:0:0/device/vendor": "SEAGATE\n",
                "/sys/class/scsi_device/0:0:0:0/device/model": "ST4000NM0035\n",
                "/sys/class/scsi_device/0:0:0:0/device/type": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/state": "running\n",
                "/sys/class/scsi_device/0:0:0:0/device/iorequest_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/iodone_cnt": "999995\n",
                "/sys/class/scsi_device/0:0:0:0/device/ioerr_cnt": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/iotmo_cnt": "5\n",
            }
        )
        output = Output()

        exit_code = scsi_error_monitor.run([], output, ctx)

        assert exit_code == 1
        assert any("timeout" in i.lower() for i in output.data["devices"][0]["issues"])

    def test_critical_errors_marked_critical(self, mock_context):
        """Marks devices with high error counts as critical."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/class/scsi_device": "",
                "/sys/class/scsi_device/0:0:0:0": "",
                "/sys/class/scsi_device/0:0:0:0/device": "",
                "/sys/class/scsi_device/0:0:0:0/device/vendor": "SEAGATE\n",
                "/sys/class/scsi_device/0:0:0:0/device/model": "ST4000NM0035\n",
                "/sys/class/scsi_device/0:0:0:0/device/type": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/state": "running\n",
                "/sys/class/scsi_device/0:0:0:0/device/iorequest_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/iodone_cnt": "998500\n",
                "/sys/class/scsi_device/0:0:0:0/device/ioerr_cnt": "1500\n",
                "/sys/class/scsi_device/0:0:0:0/device/iotmo_cnt": "0\n",
            }
        )
        output = Output()

        exit_code = scsi_error_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["devices"][0]["status"] == "critical"

    def test_disks_only_filters_non_disks(self, mock_context):
        """--disks-only filters non-disk devices."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/class/scsi_device": "",
                # Disk device (type 0)
                "/sys/class/scsi_device/0:0:0:0": "",
                "/sys/class/scsi_device/0:0:0:0/device": "",
                "/sys/class/scsi_device/0:0:0:0/device/vendor": "SEAGATE\n",
                "/sys/class/scsi_device/0:0:0:0/device/model": "ST4000NM0035\n",
                "/sys/class/scsi_device/0:0:0:0/device/type": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/state": "running\n",
                "/sys/class/scsi_device/0:0:0:0/device/iorequest_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/iodone_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/ioerr_cnt": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/iotmo_cnt": "0\n",
                # Enclosure device (type 13)
                "/sys/class/scsi_device/0:0:0:1": "",
                "/sys/class/scsi_device/0:0:0:1/device": "",
                "/sys/class/scsi_device/0:0:0:1/device/vendor": "HP\n",
                "/sys/class/scsi_device/0:0:0:1/device/model": "P420i\n",
                "/sys/class/scsi_device/0:0:0:1/device/type": "13\n",
                "/sys/class/scsi_device/0:0:0:1/device/state": "running\n",
                "/sys/class/scsi_device/0:0:0:1/device/iorequest_cnt": "100\n",
                "/sys/class/scsi_device/0:0:0:1/device/iodone_cnt": "100\n",
                "/sys/class/scsi_device/0:0:0:1/device/ioerr_cnt": "0\n",
                "/sys/class/scsi_device/0:0:0:1/device/iotmo_cnt": "0\n",
            }
        )
        output = Output()

        exit_code = scsi_error_monitor.run(["--disks-only"], output, ctx)

        assert exit_code == 0
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["type"] == "disk"

    def test_verbose_includes_counters(self, mock_context):
        """Verbose mode includes counter details in output."""
        from scripts.baremetal import scsi_error_monitor

        ctx = mock_context(
            file_contents={
                "/sys/class/scsi_device": "",
                "/sys/class/scsi_device/0:0:0:0": "",
                "/sys/class/scsi_device/0:0:0:0/device": "",
                "/sys/class/scsi_device/0:0:0:0/device/vendor": "SEAGATE\n",
                "/sys/class/scsi_device/0:0:0:0/device/model": "ST4000NM0035\n",
                "/sys/class/scsi_device/0:0:0:0/device/type": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/state": "running\n",
                "/sys/class/scsi_device/0:0:0:0/device/iorequest_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/iodone_cnt": "1000000\n",
                "/sys/class/scsi_device/0:0:0:0/device/ioerr_cnt": "0\n",
                "/sys/class/scsi_device/0:0:0:0/device/iotmo_cnt": "0\n",
            }
        )
        output = Output()

        exit_code = scsi_error_monitor.run(["-v"], output, ctx)

        assert exit_code == 0
        assert "counters" in output.data["devices"][0]
        assert output.data["devices"][0]["counters"]["iorequest_cnt"] == 1000000
