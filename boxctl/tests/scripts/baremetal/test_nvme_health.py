"""Tests for nvme_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def nvme_smart_healthy(fixtures_dir):
    """Load healthy NVMe SMART output."""
    return (fixtures_dir / "storage" / "nvme_smart_healthy.txt").read_text()


@pytest.fixture
def nvme_smart_high_temp(fixtures_dir):
    """Load high temperature NVMe SMART output."""
    return (fixtures_dir / "storage" / "nvme_smart_high_temp.txt").read_text()


@pytest.fixture
def nvme_smart_critical_warning(fixtures_dir):
    """Load critical warning NVMe SMART output."""
    return (fixtures_dir / "storage" / "nvme_smart_critical_warning.txt").read_text()


@pytest.fixture
def nvme_smart_media_errors(fixtures_dir):
    """Load media errors NVMe SMART output."""
    return (fixtures_dir / "storage" / "nvme_smart_media_errors.txt").read_text()


@pytest.fixture
def nvme_smart_endurance_exceeded(fixtures_dir):
    """Load endurance exceeded NVMe SMART output."""
    return (fixtures_dir / "storage" / "nvme_smart_endurance_exceeded.txt").read_text()


@pytest.fixture
def nvme_id_ctrl(fixtures_dir):
    """Load NVMe controller identification output."""
    return (fixtures_dir / "storage" / "nvme_id_ctrl.txt").read_text()


class TestNvmeHealth:
    """Tests for nvme_health script."""

    def test_missing_nvme_returns_error(self, mock_context):
        """Returns exit code 2 when nvme-cli not available."""
        from scripts.baremetal import nvme_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = nvme_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("nvme" in e.lower() for e in output.errors)

    def test_no_nvme_devices(self, mock_context):
        """Returns 0 when no NVMe devices found."""
        from scripts.baremetal import nvme_health

        ctx = mock_context(
            tools_available=["nvme"],
            file_contents={},  # No /dev/nvme* files
        )
        output = Output()

        exit_code = nvme_health.run([], output, ctx)

        assert exit_code == 0
        assert "drives" in output.data
        assert len(output.data["drives"]) == 0

    def test_all_drives_healthy(self, mock_context, nvme_smart_healthy, nvme_id_ctrl):
        """Returns 0 when all NVMe drives are healthy."""
        from scripts.baremetal import nvme_health

        ctx = mock_context(
            tools_available=["nvme"],
            command_outputs={
                ("nvme", "smart-log", "/dev/nvme0n1"): nvme_smart_healthy,
                ("nvme", "id-ctrl", "/dev/nvme0"): nvme_id_ctrl,
            },
            file_contents={
                "/dev/nvme0n1": "",  # Indicate device exists
            }
        )
        output = Output()

        exit_code = nvme_health.run(["--device", "/dev/nvme0n1"], output, ctx)

        assert exit_code == 0
        assert len(output.data["drives"]) == 1
        assert output.data["drives"][0]["status"] == "healthy"

    def test_high_temperature_warning(self, mock_context, nvme_smart_high_temp, nvme_id_ctrl):
        """Returns 1 when temperature exceeds warning threshold."""
        from scripts.baremetal import nvme_health

        ctx = mock_context(
            tools_available=["nvme"],
            command_outputs={
                ("nvme", "smart-log", "/dev/nvme0n1"): nvme_smart_high_temp,
                ("nvme", "id-ctrl", "/dev/nvme0"): nvme_id_ctrl,
            },
            file_contents={
                "/dev/nvme0n1": "",
            }
        )
        output = Output()

        exit_code = nvme_health.run(["--device", "/dev/nvme0n1"], output, ctx)

        assert exit_code == 1
        assert output.data["drives"][0]["status"] in ("warning", "critical")
        assert any("temperature" in w["type"].lower()
                   for w in output.data["drives"][0].get("warnings", []))

    def test_critical_warning_flag(self, mock_context, nvme_smart_critical_warning, nvme_id_ctrl):
        """Returns 1 when critical warning flag is set."""
        from scripts.baremetal import nvme_health

        ctx = mock_context(
            tools_available=["nvme"],
            command_outputs={
                ("nvme", "smart-log", "/dev/nvme0n1"): nvme_smart_critical_warning,
                ("nvme", "id-ctrl", "/dev/nvme0"): nvme_id_ctrl,
            },
            file_contents={
                "/dev/nvme0n1": "",
            }
        )
        output = Output()

        exit_code = nvme_health.run(["--device", "/dev/nvme0n1"], output, ctx)

        assert exit_code == 1
        assert output.data["drives"][0]["status"] == "critical"
        assert any("critical_warning" in i["type"] or "spare" in i["type"].lower()
                   for i in output.data["drives"][0].get("issues", []))

    def test_media_errors_detected(self, mock_context, nvme_smart_media_errors, nvme_id_ctrl):
        """Returns 1 when media errors are detected."""
        from scripts.baremetal import nvme_health

        ctx = mock_context(
            tools_available=["nvme"],
            command_outputs={
                ("nvme", "smart-log", "/dev/nvme0n1"): nvme_smart_media_errors,
                ("nvme", "id-ctrl", "/dev/nvme0"): nvme_id_ctrl,
            },
            file_contents={
                "/dev/nvme0n1": "",
            }
        )
        output = Output()

        exit_code = nvme_health.run(["--device", "/dev/nvme0n1"], output, ctx)

        assert exit_code == 1
        assert output.data["drives"][0]["status"] == "critical"
        assert any("media" in i["type"].lower()
                   for i in output.data["drives"][0].get("issues", []))

    def test_endurance_exceeded(self, mock_context, nvme_smart_endurance_exceeded, nvme_id_ctrl):
        """Returns 1 when endurance is exceeded."""
        from scripts.baremetal import nvme_health

        ctx = mock_context(
            tools_available=["nvme"],
            command_outputs={
                ("nvme", "smart-log", "/dev/nvme0n1"): nvme_smart_endurance_exceeded,
                ("nvme", "id-ctrl", "/dev/nvme0"): nvme_id_ctrl,
            },
            file_contents={
                "/dev/nvme0n1": "",
            }
        )
        output = Output()

        exit_code = nvme_health.run(["--device", "/dev/nvme0n1"], output, ctx)

        assert exit_code == 1
        assert output.data["drives"][0]["status"] == "critical"
        assert any("endurance" in i["type"].lower()
                   for i in output.data["drives"][0].get("issues", []))
