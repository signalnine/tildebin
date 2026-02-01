"""Tests for psu_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def psu_healthy(fixtures_dir):
    """Load healthy PSU output."""
    return (fixtures_dir / "ipmitool" / "psu_healthy.txt").read_text()


@pytest.fixture
def psu_warning(fixtures_dir):
    """Load warning PSU output."""
    return (fixtures_dir / "ipmitool" / "psu_warning.txt").read_text()


@pytest.fixture
def psu_failure(fixtures_dir):
    """Load PSU failure output."""
    return (fixtures_dir / "ipmitool" / "psu_failure.txt").read_text()


@pytest.fixture
def voltage_healthy(fixtures_dir):
    """Load healthy voltage output."""
    return (fixtures_dir / "ipmitool" / "voltage_healthy.txt").read_text()


@pytest.fixture
def voltage_warning(fixtures_dir):
    """Load warning voltage output."""
    return (fixtures_dir / "ipmitool" / "voltage_warning.txt").read_text()


class TestPsuMonitor:
    """Tests for psu_monitor script."""

    def test_missing_ipmitool_returns_error(self, mock_context):
        """Returns exit code 2 when ipmitool not available."""
        from scripts.baremetal import psu_monitor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = psu_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("ipmitool" in e.lower() for e in output.errors)

    def test_all_psus_healthy(self, mock_context, psu_healthy, voltage_healthy):
        """Returns 0 when all PSUs are healthy."""
        from scripts.baremetal import psu_monitor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sdr", "type", "Power Supply"): psu_healthy,
                ("ipmitool", "sdr", "type", "Voltage"): voltage_healthy,
            }
        )
        output = Output()

        exit_code = psu_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["critical"] == 0
        assert output.data["summary"]["warning"] == 0
        assert output.data["summary"]["healthy"] > 0

    def test_psu_redundancy_warning(self, mock_context, psu_warning, voltage_healthy):
        """Returns 1 when PSU redundancy lost."""
        from scripts.baremetal import psu_monitor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sdr", "type", "Power Supply"): psu_warning,
                ("ipmitool", "sdr", "type", "Voltage"): voltage_healthy,
            }
        )
        output = Output()

        exit_code = psu_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["warning"] > 0

    def test_psu_failure_detected(self, mock_context, psu_failure, voltage_healthy):
        """Returns 1 when PSU failure detected."""
        from scripts.baremetal import psu_monitor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sdr", "type", "Power Supply"): psu_failure,
                ("ipmitool", "sdr", "type", "Voltage"): voltage_healthy,
            }
        )
        output = Output()

        exit_code = psu_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["critical"] > 0

    def test_voltage_warning_detected(self, mock_context, psu_healthy, voltage_warning):
        """Returns 1 when voltage warning detected."""
        from scripts.baremetal import psu_monitor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sdr", "type", "Power Supply"): psu_healthy,
                ("ipmitool", "sdr", "type", "Voltage"): voltage_warning,
            }
        )
        output = Output()

        exit_code = psu_monitor.run([], output, ctx)

        assert exit_code == 1
        # Voltage sensor with nc status should be warning
        warning_sensors = [
            s for s in output.data["voltage_sensors"]
            if s.get("health") == "WARNING"
        ]
        assert len(warning_sensors) > 0

    def test_warn_only_filters_output(self, mock_context, psu_failure, voltage_healthy):
        """--warn-only filters to only sensors with issues."""
        from scripts.baremetal import psu_monitor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sdr", "type", "Power Supply"): psu_failure,
                ("ipmitool", "sdr", "type", "Voltage"): voltage_healthy,
            }
        )
        output = Output()

        exit_code = psu_monitor.run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # All PSU sensors should have warning or critical
        assert all(
            s.get("health") in ["WARNING", "CRITICAL"]
            for s in output.data["psu_sensors"]
        )
        # Voltage sensors should be empty (all healthy)
        assert len(output.data["voltage_sensors"]) == 0

    def test_no_sensors_found(self, mock_context):
        """Handles case when no PSU sensors found."""
        from scripts.baremetal import psu_monitor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sdr", "type", "Power Supply"): "",
                ("ipmitool", "sdr", "type", "Voltage"): "",
            }
        )
        output = Output()

        exit_code = psu_monitor.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["psu_sensors"]) == 0
        assert "No PSU sensors" in output.summary
