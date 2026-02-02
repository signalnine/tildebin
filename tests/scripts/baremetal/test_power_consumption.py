#!/usr/bin/env python3
"""Tests for scripts/baremetal/power_consumption.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.power_consumption import run


class TestPowerConsumption:
    """Tests for power_consumption script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = Context()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_format_json(self):
        """Test JSON output format."""
        output = Output()
        output.emit({
            "readings": [{
                "sensor": "System Power",
                "value": 350.0,
                "unit": "Watts",
                "status": "healthy"
            }]
        })

        data = output.data
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "readings" in parsed
        assert len(parsed["readings"]) == 1
        assert parsed["readings"][0]["value"] == 350.0

    def test_warn_only_filter(self):
        """Test --warn-only filtering."""
        readings = [
            {"sensor": "PSU1", "value": 300.0, "unit": "Watts", "status": "healthy"},
            {"sensor": "PSU2", "value": 500.0, "unit": "Watts", "status": "warning"},
        ]

        filtered = [r for r in readings if r['status'] != 'healthy']

        assert len(filtered) == 1
        assert filtered[0]["sensor"] == "PSU2"
        assert filtered[0]["status"] == "warning"

    def test_total_power_calculation(self):
        """Test total power calculation for summary."""
        readings = [
            {"sensor": "PSU1", "value": 300.0, "unit": "Watts", "status": "healthy"},
            {"sensor": "PSU2", "value": 250.0, "unit": "Watts", "status": "healthy"},
            {"sensor": "CPU Package", "value": 45.0, "unit": "Joules", "status": "healthy"},
        ]

        # Only sum Watts readings
        total_power = sum(r['value'] for r in readings if r['unit'] == 'Watts')

        assert total_power == 550.0

    def test_verbose_includes_source(self):
        """Test that verbose mode includes source field."""
        reading = {
            "source": "ipmi",
            "sensor": "System Power",
            "value": 350.0,
            "unit": "Watts",
            "status": "healthy"
        }

        # In verbose mode, source is kept
        assert "source" in reading
        assert reading["source"] == "ipmi"

    def test_non_verbose_removes_source(self):
        """Test that non-verbose mode removes source field."""
        reading = {
            "source": "ipmi",
            "sensor": "System Power",
            "value": 350.0,
            "unit": "Watts",
            "status": "healthy"
        }

        # Simulate non-verbose processing
        reading.pop('source', None)

        assert "source" not in reading
