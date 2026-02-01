"""Tests for ipmi_sensor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def sensor_healthy(fixtures_dir):
    """Load healthy sensor output."""
    return (fixtures_dir / "ipmitool" / "sensor_healthy.txt").read_text()


@pytest.fixture
def sensor_warning(fixtures_dir):
    """Load warning sensor output."""
    return (fixtures_dir / "ipmitool" / "sensor_warning.txt").read_text()


@pytest.fixture
def sensor_critical(fixtures_dir):
    """Load critical sensor output."""
    return (fixtures_dir / "ipmitool" / "sensor_critical.txt").read_text()


@pytest.fixture
def sensor_fan_failure(fixtures_dir):
    """Load fan failure sensor output."""
    return (fixtures_dir / "ipmitool" / "sensor_fan_failure.txt").read_text()


class TestIpmiSensor:
    """Tests for ipmi_sensor script."""

    def test_missing_ipmitool_returns_error(self, mock_context):
        """Returns exit code 2 when ipmitool not available."""
        from scripts.baremetal import ipmi_sensor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = ipmi_sensor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("ipmitool" in e.lower() for e in output.errors)

    def test_all_sensors_healthy(self, mock_context, sensor_healthy):
        """Returns 0 when all sensors are healthy."""
        from scripts.baremetal import ipmi_sensor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sensor", "list"): sensor_healthy,
            }
        )
        output = Output()

        exit_code = ipmi_sensor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["critical"] == 0
        assert output.data["summary"]["warning"] == 0
        assert output.data["summary"]["ok"] > 0

    def test_warning_sensor_detected(self, mock_context, sensor_warning):
        """Returns 1 when warning-level sensors detected."""
        from scripts.baremetal import ipmi_sensor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sensor", "list"): sensor_warning,
            }
        )
        output = Output()

        exit_code = ipmi_sensor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["warning"] > 0

    def test_critical_sensor_detected(self, mock_context, sensor_critical):
        """Returns 1 when critical sensors detected."""
        from scripts.baremetal import ipmi_sensor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sensor", "list"): sensor_critical,
            }
        )
        output = Output()

        exit_code = ipmi_sensor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["critical"] > 0

    def test_fan_failure_detected(self, mock_context, sensor_fan_failure):
        """Detects fan failure (0 RPM with critical status)."""
        from scripts.baremetal import ipmi_sensor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sensor", "list"): sensor_fan_failure,
            }
        )
        output = Output()

        exit_code = ipmi_sensor.run([], output, ctx)

        assert exit_code == 1
        fan_sensors = [s for s in output.data["sensors"] if s["type"] == "fan"]
        failed_fans = [s for s in fan_sensors if s["severity"] == "critical"]
        assert len(failed_fans) == 2

    def test_type_filter(self, mock_context, sensor_healthy):
        """--type filters to specific sensor types."""
        from scripts.baremetal import ipmi_sensor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sensor", "list"): sensor_healthy,
            }
        )
        output = Output()

        exit_code = ipmi_sensor.run(["--type", "temperature"], output, ctx)

        assert exit_code == 0
        assert all(s["type"] == "temperature" for s in output.data["sensors"])
        # Should have CPU Temp, System Temp, Inlet Temp
        assert len(output.data["sensors"]) == 3

    def test_warn_only_filters_output(self, mock_context, sensor_critical):
        """--warn-only filters to only sensors with issues."""
        from scripts.baremetal import ipmi_sensor

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sensor", "list"): sensor_critical,
            }
        )
        output = Output()

        exit_code = ipmi_sensor.run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # All returned sensors should have warning or critical severity
        assert all(
            s["severity"] in ("warning", "critical")
            for s in output.data["sensors"]
        )

    def test_custom_temp_thresholds(self, mock_context):
        """Custom temperature thresholds affect severity."""
        from scripts.baremetal import ipmi_sensor

        sensor_data = "CPU Temp | 72.000 | degrees C | ok | 0 | 0 | 0 | 85 | 90 | 95"

        ctx = mock_context(
            tools_available=["ipmitool"],
            command_outputs={
                ("ipmitool", "sensor", "list"): sensor_data,
            }
        )
        output = Output()

        # With default thresholds (75 warn), 72C should be OK
        exit_code = ipmi_sensor.run([], output, ctx)
        assert exit_code == 0

        # With lower thresholds (70 warn), 72C should be warning
        output2 = Output()
        exit_code2 = ipmi_sensor.run(["--temp-warn", "70"], output2, ctx)
        assert exit_code2 == 1
        assert output2.data["sensors"][0]["severity"] == "warning"
