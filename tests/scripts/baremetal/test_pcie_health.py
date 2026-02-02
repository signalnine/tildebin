#!/usr/bin/env python3
"""Tests for scripts/baremetal/pcie_health.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.pcie_health import (
    run,
    parse_pcie_speed,
    parse_pcie_width,
    check_device_health
)


class TestPcieHealth:
    """Tests for pcie_health script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = Context()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_parse_pcie_speed(self):
        """Test parsing PCIe speed strings."""
        assert parse_pcie_speed("2.5GT/s") == 2.5
        assert parse_pcie_speed("5GT/s") == 5.0
        assert parse_pcie_speed("8GT/s") == 8.0
        assert parse_pcie_speed("16GT/s") == 16.0
        assert parse_pcie_speed("invalid") == 0.0

    def test_parse_pcie_width(self):
        """Test parsing PCIe width strings."""
        assert parse_pcie_width("x1") == 1
        assert parse_pcie_width("x4") == 4
        assert parse_pcie_width("x8") == 8
        assert parse_pcie_width("x16") == 16
        assert parse_pcie_width("invalid") == 0

    def test_check_device_health_healthy(self):
        """Test healthy device detection."""
        details = {
            'lnk_cap_speed': '8GT/s',
            'lnk_cap_width': 'x16',
            'lnk_sta_speed': '8GT/s',
            'lnk_sta_width': 'x16',
            'correctable_errors': 0,
            'uncorrectable_errors': 0,
            'fatal_errors': 0
        }

        health = check_device_health(details)
        assert health['status'] == 'healthy'
        assert len(health['issues']) == 0

    def test_check_device_health_speed_degraded(self):
        """Test speed degradation detection."""
        details = {
            'lnk_cap_speed': '8GT/s',
            'lnk_cap_width': 'x16',
            'lnk_sta_speed': '2.5GT/s',  # Degraded
            'lnk_sta_width': 'x16',
            'correctable_errors': 0,
            'uncorrectable_errors': 0,
            'fatal_errors': 0
        }

        health = check_device_health(details)
        assert health['status'] == 'warning'
        assert any('speed' in issue.lower() for issue in health['issues'])

    def test_check_device_health_width_degraded(self):
        """Test width degradation detection."""
        details = {
            'lnk_cap_speed': '8GT/s',
            'lnk_cap_width': 'x16',
            'lnk_sta_speed': '8GT/s',
            'lnk_sta_width': 'x4',  # Degraded
            'correctable_errors': 0,
            'uncorrectable_errors': 0,
            'fatal_errors': 0
        }

        health = check_device_health(details)
        assert health['status'] == 'warning'
        assert any('width' in issue.lower() for issue in health['issues'])

    def test_check_device_health_fatal_errors(self):
        """Test fatal error detection."""
        details = {
            'lnk_cap_speed': '8GT/s',
            'lnk_cap_width': 'x16',
            'lnk_sta_speed': '8GT/s',
            'lnk_sta_width': 'x16',
            'correctable_errors': 0,
            'uncorrectable_errors': 0,
            'fatal_errors': 1
        }

        health = check_device_health(details)
        assert health['status'] == 'critical'
        assert any('fatal' in issue.lower() for issue in health['issues'])

    def test_check_device_health_uncorrectable_errors(self):
        """Test uncorrectable error detection."""
        details = {
            'lnk_cap_speed': '8GT/s',
            'lnk_cap_width': 'x16',
            'lnk_sta_speed': '8GT/s',
            'lnk_sta_width': 'x16',
            'correctable_errors': 0,
            'uncorrectable_errors': 3,
            'fatal_errors': 0
        }

        health = check_device_health(details)
        assert health['status'] == 'critical'
        assert any('uncorrectable' in issue.lower() for issue in health['issues'])

    def test_check_device_health_correctable_errors(self):
        """Test correctable error detection."""
        details = {
            'lnk_cap_speed': '8GT/s',
            'lnk_cap_width': 'x16',
            'lnk_sta_speed': '8GT/s',
            'lnk_sta_width': 'x16',
            'correctable_errors': 2,
            'uncorrectable_errors': 0,
            'fatal_errors': 0
        }

        health = check_device_health(details)
        assert health['status'] == 'warning'
        assert any('correctable' in issue.lower() for issue in health['issues'])

    def test_check_device_health_no_link_info(self):
        """Test handling devices without link information."""
        details = {
            'lnk_cap_speed': None,
            'lnk_sta_speed': None,
        }

        health = check_device_health(details)
        assert health['status'] == 'n/a'

    def test_format_json(self):
        """Test JSON output format."""
        output = Output()
        output.emit({
            "devices": [{
                "address": "0000:01:00.0",
                "description": "VGA compatible controller",
                "status": "healthy"
            }]
        })

        data = output.data
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "devices" in parsed
        assert len(parsed["devices"]) == 1
        assert parsed["devices"][0]["status"] == "healthy"
