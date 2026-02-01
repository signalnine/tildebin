"""Tests for disk_life_predictor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "smartctl"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestDiskLifePredictor:
    """Tests for disk_life_predictor."""

    def test_missing_smartctl_returns_error(self, mock_context):
        """Returns exit code 2 when smartctl not available."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(tools_available=["lsblk"])
        output = Output()

        result = run([], output, ctx)

        assert result == 2
        assert len(output.errors) > 0
        assert any("smartctl" in e.lower() for e in output.errors)

    def test_healthy_disk_minimal_risk(self, mock_context):
        """Healthy disk returns MINIMAL risk."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD\n",
                ("smartctl", "-H", "-A", "/dev/sda"): load_fixture("predictor_healthy.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert output.data["disks"][0]["risk_level"] == "MINIMAL"
        assert output.data["disks"][0]["risk_score"] == 0

    def test_low_risk_disk(self, mock_context):
        """Disk with minor issues returns LOW risk."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "1T WDC\n",
                ("smartctl", "-H", "-A", "/dev/sda"): load_fixture("predictor_low_risk.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["disks"][0]["risk_level"] == "LOW"
        assert output.data["disks"][0]["risk_score"] >= 10

    def test_medium_risk_disk(self, mock_context):
        """Disk with elevated issues returns MEDIUM risk."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "2T Seagate\n",
                ("smartctl", "-H", "-A", "/dev/sda"): load_fixture("predictor_medium_risk.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["disks"][0]["risk_level"] == "MEDIUM"
        assert 30 <= output.data["disks"][0]["risk_score"] < 60

    def test_high_risk_disk(self, mock_context):
        """Disk with serious issues returns HIGH risk."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "1T Seagate\n",
                ("smartctl", "-H", "-A", "/dev/sda"): load_fixture("predictor_high_risk.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["disks"][0]["risk_level"] == "HIGH"
        assert output.data["disks"][0]["risk_score"] >= 60

    def test_failed_smart_health(self, mock_context):
        """Disk with SMART FAILED returns HIGH risk."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Seagate\n",
                ("smartctl", "-H", "-A", "/dev/sda"): load_fixture("predictor_failed.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        disk = output.data["disks"][0]
        assert disk["risk_level"] == "HIGH"
        assert disk["smart_status"] == "FAILED"
        assert any("FAILED" in f["message"] for f in disk["findings"])

    def test_warn_only_mode(self, mock_context):
        """--warn-only filters to show only risky disks."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "500G Samsung SSD\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sdb"): "1T Seagate\n",
                ("smartctl", "-H", "-A", "/dev/sda"): load_fixture("predictor_healthy.txt"),
                ("smartctl", "-H", "-A", "/dev/sdb"): load_fixture("predictor_high_risk.txt"),
            }
        )
        output = Output()

        result = run(["--warn-only"], output, ctx)

        assert result == 1
        # Only risky disk should be shown
        assert len(output.data["disks"]) == 1
        assert output.data["disks"][0]["risk_level"] == "HIGH"

    def test_findings_contain_details(self, mock_context):
        """Findings include attribute details."""
        from scripts.baremetal.disk_life_predictor import run

        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\n",
                ("lsblk", "-n", "-o", "SIZE,MODEL", "/dev/sda"): "2T Seagate\n",
                ("smartctl", "-H", "-A", "/dev/sda"): load_fixture("predictor_medium_risk.txt"),
            }
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        findings = output.data["disks"][0]["findings"]
        assert len(findings) > 0
        # Should have findings about sectors or other attributes
        assert any("severity" in f for f in findings)
        assert any("message" in f for f in findings)
