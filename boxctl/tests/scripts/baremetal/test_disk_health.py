"""Tests for disk_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def smartctl_healthy(fixtures_dir):
    """Load healthy SSD smartctl output."""
    return (fixtures_dir / "smartctl" / "healthy_ssd.txt").read_text()


@pytest.fixture
def smartctl_failing(fixtures_dir):
    """Load failing HDD smartctl output."""
    return (fixtures_dir / "smartctl" / "failing_hdd.txt").read_text()


class TestDiskHealth:
    """Tests for disk_health script."""

    def test_missing_smartctl_returns_error(self, mock_context):
        """Returns exit code 2 when smartctl not available."""
        from scripts.baremetal import disk_health

        ctx = mock_context(tools_available=["lsblk"])
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("smartctl" in e.lower() for e in output.errors)

    def test_all_disks_healthy(self, mock_context, smartctl_healthy):
        """Returns 0 when all disks pass SMART."""
        from scripts.baremetal import disk_health

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk\n",
                ("smartctl", "-H", "/dev/sda"): smartctl_healthy,
                ("smartctl", "-H", "/dev/sdb"): smartctl_healthy,
            }
        )
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["disks"]) == 2
        assert all(d["status"] == "PASSED" for d in output.data["disks"])

    def test_one_disk_failing(self, mock_context, smartctl_healthy, smartctl_failing):
        """Returns 1 when one disk fails SMART."""
        from scripts.baremetal import disk_health

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk\n",
                ("smartctl", "-H", "/dev/sda"): smartctl_healthy,
                ("smartctl", "-H", "/dev/sdb"): smartctl_failing,
            }
        )
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["disks"][0]["status"] == "PASSED"
        assert output.data["disks"][1]["status"] == "FAILED"

    def test_verbose_output(self, mock_context, smartctl_healthy):
        """--verbose shows additional details."""
        from scripts.baremetal import disk_health

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("smartctl", "-H", "/dev/sda"): smartctl_healthy,
            }
        )
        output = Output()

        exit_code = disk_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        # Verbose mode should include model info
        assert "model" in output.data["disks"][0]

    def test_no_disks_found(self, mock_context):
        """Returns 1 with warning when no disks found."""
        from scripts.baremetal import disk_health

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "",
            }
        )
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 1
        assert len(output.warnings) > 0
