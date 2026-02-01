"""Tests for ssd_wear script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def smartctl_ssd_healthy(fixtures_dir):
    """Load healthy SSD smartctl output."""
    return (fixtures_dir / "storage" / "smartctl_ssd_healthy.txt").read_text()


@pytest.fixture
def smartctl_ssd_low_wear(fixtures_dir):
    """Load low wear SSD smartctl output."""
    return (fixtures_dir / "storage" / "smartctl_ssd_low_wear.txt").read_text()


@pytest.fixture
def smartctl_ssd_critical_wear(fixtures_dir):
    """Load critical wear SSD smartctl output."""
    return (fixtures_dir / "storage" / "smartctl_ssd_critical_wear.txt").read_text()


@pytest.fixture
def smartctl_ssd_media_errors(fixtures_dir):
    """Load media errors SSD smartctl output."""
    return (fixtures_dir / "storage" / "smartctl_ssd_media_errors.txt").read_text()


@pytest.fixture
def smartctl_nvme_ssd_healthy(fixtures_dir):
    """Load healthy NVMe SSD smartctl output."""
    return (fixtures_dir / "storage" / "smartctl_nvme_ssd_healthy.txt").read_text()


@pytest.fixture
def lsblk_ssds(fixtures_dir):
    """Load lsblk output with SSDs."""
    return (fixtures_dir / "storage" / "lsblk_ssds.txt").read_text()


class TestSsdWear:
    """Tests for ssd_wear script."""

    def test_missing_smartctl_returns_error(self, mock_context):
        """Returns exit code 2 when smartctl not available."""
        from scripts.baremetal import ssd_wear

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = ssd_wear.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("smartctl" in e.lower() for e in output.errors)

    def test_no_ssds_found(self, mock_context):
        """Returns 0 when no SSDs found."""
        from scripts.baremetal import ssd_wear

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "",
            },
            file_contents={},
        )
        output = Output()

        exit_code = ssd_wear.run([], output, ctx)

        assert exit_code == 0
        assert "ssds" in output.data
        assert len(output.data["ssds"]) == 0

    def test_ssd_healthy(self, mock_context, smartctl_ssd_healthy, lsblk_ssds):
        """Returns 0 when SSD is healthy with good wear level."""
        from scripts.baremetal import ssd_wear

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("smartctl", "-A", "/dev/sda"): smartctl_ssd_healthy,
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD 860 EVO\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
            }
        )
        output = Output()

        exit_code = ssd_wear.run(["--disk", "/dev/sda"], output, ctx)

        assert exit_code == 0
        assert len(output.data["ssds"]) == 1
        assert output.data["ssds"][0]["status"] == "healthy"
        assert output.data["ssds"][0]["wear_level"] == 95

    def test_ssd_low_wear_warning(self, mock_context, smartctl_ssd_low_wear):
        """Returns 1 when SSD has low wear level (warning threshold)."""
        from scripts.baremetal import ssd_wear

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("smartctl", "-A", "/dev/sda"): smartctl_ssd_low_wear,
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD 860 EVO\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
            }
        )
        output = Output()

        exit_code = ssd_wear.run(["--disk", "/dev/sda"], output, ctx)

        assert exit_code == 1
        assert output.data["ssds"][0]["status"] == "warning"
        assert output.data["ssds"][0]["wear_level"] == 15

    def test_ssd_critical_wear(self, mock_context, smartctl_ssd_critical_wear):
        """Returns 1 when SSD has critically low wear level."""
        from scripts.baremetal import ssd_wear

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("smartctl", "-A", "/dev/sda"): smartctl_ssd_critical_wear,
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD 860 EVO\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
            }
        )
        output = Output()

        exit_code = ssd_wear.run(["--disk", "/dev/sda"], output, ctx)

        assert exit_code == 1
        assert output.data["ssds"][0]["status"] == "critical"
        assert output.data["ssds"][0]["wear_level"] == 5

    def test_ssd_media_errors(self, mock_context, smartctl_ssd_media_errors):
        """Returns 1 when SSD has media errors (reallocated sectors)."""
        from scripts.baremetal import ssd_wear

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("smartctl", "-A", "/dev/sda"): smartctl_ssd_media_errors,
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD 860 EVO\n",
            },
            file_contents={
                "/sys/block/sda/queue/rotational": "0",
            }
        )
        output = Output()

        exit_code = ssd_wear.run(["--disk", "/dev/sda"], output, ctx)

        assert exit_code == 1
        assert output.data["ssds"][0]["status"] == "critical"
        assert output.data["ssds"][0]["media_errors"] > 0

    def test_nvme_ssd(self, mock_context, smartctl_nvme_ssd_healthy):
        """Returns 0 for healthy NVMe SSD."""
        from scripts.baremetal import ssd_wear

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "nvme0n1 disk\n",
                ("smartctl", "-A", "/dev/nvme0n1"): smartctl_nvme_ssd_healthy,
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/nvme0n1"): "1T Samsung SSD 980 PRO\n",
            },
            file_contents={
                "/sys/block/nvme0n1/queue/rotational": "0",
            }
        )
        output = Output()

        exit_code = ssd_wear.run(["--disk", "/dev/nvme0n1"], output, ctx)

        assert exit_code == 0
        assert len(output.data["ssds"]) == 1
        assert output.data["ssds"][0]["status"] == "healthy"
