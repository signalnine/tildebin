#!/usr/bin/env python3
"""Tests for scripts/baremetal/hardware_temperature.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.hardware_temperature import run, parse_sensors_output


class TestHardwareTemperature:
    """Tests for hardware_temperature script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = Context()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_parse_temperature_sensor(self):
        """Test parsing temperature sensor output."""
        sensors_output = """coretemp-isa-0000
Adapter: ISA adapter
Core 0:        +45.0 C  (high = +80.0 C, crit = +100.0 C)
Core 1:        +47.0 C  (high = +80.0 C, crit = +100.0 C)
"""
        sensors = parse_sensors_output(sensors_output)

        assert len(sensors) == 2
        assert sensors[0]['chip'] == 'coretemp-isa-0000'
        assert sensors[0]['label'] == 'Core 0'
        assert sensors[0]['type'] == 'temperature'
        assert sensors[0]['value'] == 45.0
        assert sensors[0]['high'] == 80.0
        assert sensors[0]['critical'] == 100.0
        assert sensors[0]['status'] == 'healthy'

    def test_parse_fan_sensor(self):
        """Test parsing fan sensor output."""
        sensors_output = """nct6795-isa-0290
Adapter: ISA adapter
fan1:         1234 RPM  (min =  600 RPM)
fan2:            0 RPM  (min =  600 RPM)
"""
        sensors = parse_sensors_output(sensors_output)

        assert len(sensors) == 2
        assert sensors[0]['type'] == 'fan'
        assert sensors[0]['value'] == 1234
        assert sensors[0]['unit'] == 'RPM'
        assert sensors[0]['min'] == 600
        assert sensors[0]['status'] == 'healthy'

        # Second fan is at 0 RPM - critical
        assert sensors[1]['value'] == 0
        assert sensors[1]['status'] == 'critical'

    def test_parse_high_temperature(self):
        """Test detecting high temperature."""
        sensors_output = """coretemp-isa-0000
Core 0:        +85.0 C  (high = +80.0 C, crit = +100.0 C)
"""
        sensors = parse_sensors_output(sensors_output)

        assert len(sensors) == 1
        assert sensors[0]['value'] == 85.0
        assert sensors[0]['status'] == 'warning'

    def test_parse_critical_temperature(self):
        """Test detecting critical temperature."""
        sensors_output = """coretemp-isa-0000
Core 0:        +105.0 C  (high = +80.0 C, crit = +100.0 C)
"""
        sensors = parse_sensors_output(sensors_output)

        assert len(sensors) == 1
        assert sensors[0]['value'] == 105.0
        assert sensors[0]['status'] == 'critical'

    def test_parse_low_fan_speed(self):
        """Test detecting low fan speed."""
        sensors_output = """nct6795-isa-0290
fan1:          500 RPM  (min =  600 RPM)
"""
        sensors = parse_sensors_output(sensors_output)

        assert len(sensors) == 1
        assert sensors[0]['value'] == 500
        assert sensors[0]['status'] == 'warning'

    def test_format_json(self):
        """Test JSON output format."""
        output = Output()
        output.emit({
            "sensors": [{
                "chip": "coretemp-isa-0000",
                "label": "Core 0",
                "type": "temperature",
                "value": 45.0,
                "unit": "C",
                "status": "healthy"
            }]
        })

        data = output.get_data()
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "sensors" in parsed
        assert len(parsed["sensors"]) == 1
        assert parsed["sensors"][0]["status"] == "healthy"
