"""Tests for trim_status_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


SYSFS_DIR = Path(__file__).parent.parent.parent / "fixtures" / "sysfs"
PROC_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"
SYSTEMD_DIR = Path(__file__).parent.parent.parent / "fixtures" / "systemd"


def load_sysfs_fixture(name: str) -> str:
    """Load a sysfs fixture file."""
    return (SYSFS_DIR / name).read_text()


def load_proc_fixture(name: str) -> str:
    """Load a proc fixture file."""
    return (PROC_DIR / name).read_text()


def load_systemd_fixture(name: str) -> str:
    """Load a systemd fixture file."""
    return (SYSTEMD_DIR / name).read_text()


class TestTrimStatusMonitor:
    """Tests for trim_status_monitor."""

    def test_no_ssds_found(self, mock_context):
        """Returns 0 with warning when no SSDs found."""
        from scripts.baremetal.trim_status_monitor import run

        ctx = mock_context(
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("mount",): "",
                ("systemctl", "is-enabled", "fstrim.timer"): "enabled",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "1",  # HDD, not SSD
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert len(output.warnings) > 0 or output.data["devices"] == []

    def test_ssd_with_discard_supported_and_timer(self, mock_context):
        """SSD with TRIM support and fstrim timer enabled returns OK."""
        from scripts.baremetal.trim_status_monitor import run

        ctx = mock_context(
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD 860\n",
                ("lsblk", "-n", "-o", "NAME", "/dev/sda"): "sda\nsda1\nsda2\n",
                ("mount",): "/dev/sda1 on / type ext4 (rw,relatime)\n/dev/sda2 on /home type ext4 (rw,relatime)\n",
                ("systemctl", "is-enabled", "fstrim.timer"): "enabled\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/discard_granularity": load_sysfs_fixture("discard_supported.txt"),
                "/sys/block/sda/queue/discard_max_bytes": load_sysfs_fixture("discard_max_bytes.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert output.data["devices"][0]["discard_supported"] is True
        assert output.data["devices"][0]["status"] == "OK"
        assert output.data["fstrim_timer_enabled"] is True

    def test_ssd_without_discard_support(self, mock_context):
        """SSD without TRIM support returns WARNING."""
        from scripts.baremetal.trim_status_monitor import run

        ctx = mock_context(
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "120G OldSSD\n",
                ("lsblk", "-n", "-o", "NAME", "/dev/sda"): "sda\n",
                ("mount",): "",
                ("systemctl", "is-enabled", "fstrim.timer"): "disabled\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/discard_granularity": load_sysfs_fixture("discard_not_supported.txt"),
                "/sys/block/sda/queue/discard_max_bytes": "0",
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["devices"][0]["discard_supported"] is False
        assert output.data["devices"][0]["status"] == "WARNING"

    def test_ssd_mounted_without_discard_no_timer(self, mock_context):
        """SSD mounted without discard and no fstrim timer returns WARNING."""
        from scripts.baremetal.trim_status_monitor import run

        ctx = mock_context(
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD\n",
                ("lsblk", "-n", "-o", "NAME", "/dev/sda"): "sda\nsda1\n",
                ("mount",): "/dev/sda1 on / type ext4 (rw,relatime)\n",  # No discard option
                ("systemctl", "is-enabled", "fstrim.timer"): "disabled\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/discard_granularity": load_sysfs_fixture("discard_supported.txt"),
                "/sys/block/sda/queue/discard_max_bytes": load_sysfs_fixture("discard_max_bytes.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["devices"][0]["status"] == "WARNING"
        assert any("fstrim" in i["message"].lower() for i in output.data["devices"][0]["issues"])

    def test_ssd_with_discard_mount_option(self, mock_context):
        """SSD mounted with discard option returns OK even without timer."""
        from scripts.baremetal.trim_status_monitor import run

        ctx = mock_context(
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD\n",
                ("lsblk", "-n", "-o", "NAME", "/dev/sda"): "sda\nsda1\n",
                ("mount",): "/dev/sda1 on / type ext4 (rw,relatime,discard)\n",
                ("systemctl", "is-enabled", "fstrim.timer"): "disabled\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/discard_granularity": load_sysfs_fixture("discard_supported.txt"),
                "/sys/block/sda/queue/discard_max_bytes": load_sysfs_fixture("discard_max_bytes.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert output.data["devices"][0]["status"] == "OK"

    def test_nvme_device_detection(self, mock_context):
        """NVMe devices are detected as SSDs."""
        from scripts.baremetal.trim_status_monitor import run

        ctx = mock_context(
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "nvme0n1 disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/nvme0n1"): "1T Samsung 970 EVO\n",
                ("lsblk", "-n", "-o", "NAME", "/dev/nvme0n1"): "nvme0n1\nnvme0n1p1\n",
                ("mount",): "/dev/nvme0n1p1 on /data type xfs (rw,relatime,discard)\n",
                ("systemctl", "is-enabled", "fstrim.timer"): "enabled\n",
            },
            file_contents={
                "/sys/block/nvme0n1/queue/rotational": "0",
                "/sys/block/nvme0n1/queue/discard_granularity": load_sysfs_fixture("discard_supported.txt"),
                "/sys/block/nvme0n1/queue/discard_max_bytes": load_sysfs_fixture("discard_max_bytes.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert output.data["devices"][0]["type"] == "NVMe"
        assert output.data["devices"][0]["status"] == "OK"

    def test_warn_only_mode(self, mock_context):
        """--warn-only filters to show only problematic SSDs."""
        from scripts.baremetal.trim_status_monitor import run

        ctx = mock_context(
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sdb"): "256G OldSSD\n",
                ("lsblk", "-n", "-o", "NAME", "/dev/sda"): "sda\n",
                ("lsblk", "-n", "-o", "NAME", "/dev/sdb"): "sdb\n",
                ("mount",): "",
                ("systemctl", "is-enabled", "fstrim.timer"): "enabled\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
                "/sys/block/sda/queue/discard_granularity": load_sysfs_fixture("discard_supported.txt"),
                "/sys/block/sda/queue/discard_max_bytes": load_sysfs_fixture("discard_max_bytes.txt"),
                "/sys/block/sdb/queue/rotational": "0",
                "/sys/block/sdb/queue/discard_granularity": load_sysfs_fixture("discard_not_supported.txt"),
                "/sys/block/sdb/queue/discard_max_bytes": "0",
            }
        )
        output = Output()

        result = run(["--warn-only"], output, ctx)

        assert result == 1
        # Only the problematic device should be shown
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["device"] == "sdb"
        assert output.data["devices"][0]["status"] == "WARNING"
