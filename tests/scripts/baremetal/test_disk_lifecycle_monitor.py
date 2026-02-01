"""Tests for disk_lifecycle_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "smartctl"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestDiskLifecycleMonitor:
    """Tests for disk_lifecycle_monitor."""

    def test_missing_smartctl_returns_error(self, mock_context):
        """Returns exit code 2 when smartctl not available."""
        from scripts.baremetal.disk_lifecycle_monitor import run

        ctx = mock_context(tools_available=["lsblk"])
        output = Output()

        result = run([], output, ctx)

        assert result == 2
        assert len(output.errors) > 0
        assert any("smartctl" in e.lower() for e in output.errors)

    def test_healthy_disk(self, mock_context):
        """Returns 0 for disk with low power-on hours."""
        from scripts.baremetal.disk_lifecycle_monitor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD 860 EVO\n",
                ("smartctl", "-i", "-A", "/dev/sda"): load_fixture("lifecycle_healthy.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert len(output.data["disks"]) == 1
        assert output.data["disks"][0]["lifecycle_status"] == "healthy"
        assert output.data["disks"][0]["type"] == "SSD"

    def test_warning_disk(self, mock_context):
        """Returns 1 for disk approaching lifecycle threshold."""
        from scripts.baremetal.disk_lifecycle_monitor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "1T WD Black\n",
                ("smartctl", "-i", "-A", "/dev/sda"): load_fixture("lifecycle_warning.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["disks"][0]["lifecycle_status"] == "warning"

    def test_critical_disk(self, mock_context):
        """Returns 1 for disk past critical lifecycle threshold."""
        from scripts.baremetal.disk_lifecycle_monitor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "2T Seagate\n",
                ("smartctl", "-i", "-A", "/dev/sda"): load_fixture("lifecycle_critical.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["disks"][0]["lifecycle_status"] == "critical"

    def test_ssd_wear_detection(self, mock_context):
        """Detects SSD wear leveling issues."""
        from scripts.baremetal.disk_lifecycle_monitor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "240G Intel SSD\n",
                ("smartctl", "-i", "-A", "/dev/sda"): load_fixture("lifecycle_ssd_worn.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        disk = output.data["disks"][0]
        assert disk["type"] == "SSD"
        assert disk["lifecycle_status"] == "critical"
        assert any("wear" in c.lower() for c in disk["concerns"])

    def test_smart_unavailable(self, mock_context):
        """Handles disks without SMART support."""
        from scripts.baremetal.disk_lifecycle_monitor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "100G Virtual disk\n",
                ("smartctl", "-i", "-A", "/dev/sda"): load_fixture("lifecycle_unavailable.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert output.data["disks"][0]["smart_supported"] is False
        assert output.data["disks"][0]["lifecycle_status"] == "unknown"

    def test_verbose_output(self, mock_context):
        """--verbose shows additional SMART details."""
        from scripts.baremetal.disk_lifecycle_monitor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD\n",
                ("smartctl", "-i", "-A", "/dev/sda"): load_fixture("lifecycle_healthy.txt"),
            }
        )
        output = Output()

        result = run(["--verbose"], output, ctx)

        assert result == 0
        disk = output.data["disks"][0]
        assert "serial" in disk
        assert "firmware" in disk
