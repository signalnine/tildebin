#!/usr/bin/env python3
"""Tests for scripts/baremetal/ntp_drift.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.ntp_drift import (
    run,
    parse_chrony_tracking,
    assess_status
)


class TestNtpDrift:
    """Tests for ntp_drift script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = Context()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_parse_chrony_tracking(self):
        """Test parsing chronyc tracking output."""
        chrony_output = """Reference ID    : A9FEA97B (ntp.ubuntu.com)
Stratum         : 3
Ref time (UTC)  : Thu Nov 06 12:34:56 2025
System time     : 0.000123456 seconds fast of NTP time
Last offset     : +0.000001234 seconds
RMS offset      : 0.000012345 seconds
Frequency       : 23.456 ppm slow
Residual freq   : +0.001 ppm
Skew            : 0.123 ppm
Root delay      : 0.012345678 seconds
Root dispersion : 0.001234567 seconds
Update interval : 64.5 seconds
Leap status     : Normal
"""
        data = parse_chrony_tracking(chrony_output)

        assert data['source'] == 'chrony'
        assert data['synchronized'] is True
        assert data['reference_id'] == 'A9FEA97B'
        assert data['stratum'] == 3
        assert data['system_time_offset'] == pytest.approx(0.000123456, rel=1e-6)
        assert data['last_offset'] == pytest.approx(0.000001234, rel=1e-6)
        assert data['rms_offset'] == pytest.approx(0.000012345, rel=1e-6)
        assert data['leap_status'] == 'Normal'

    def test_parse_chrony_unsynchronized(self):
        """Test parsing unsynchronized chrony output."""
        chrony_output = """Reference ID    : 127.127.1.0
Stratum         : 16
"""
        data = parse_chrony_tracking(chrony_output)

        assert data['synchronized'] is False
        assert data['stratum'] == 16

    def test_assess_status_healthy(self):
        """Test assessing healthy status."""
        data = {
            'synchronized': True,
            'system_time_offset': 0.001,  # 1ms
            'stratum': 3
        }

        status = assess_status(data, 0.100, 1.000)
        assert status == 'healthy'

    def test_assess_status_warning(self):
        """Test assessing warning status."""
        data = {
            'synchronized': True,
            'system_time_offset': 0.200,  # 200ms
            'stratum': 3
        }

        status = assess_status(data, 0.100, 1.000)
        assert status == 'warning'

    def test_assess_status_critical_offset(self):
        """Test assessing critical status due to offset."""
        data = {
            'synchronized': True,
            'system_time_offset': 2.000,  # 2s
            'stratum': 3
        }

        status = assess_status(data, 0.100, 1.000)
        assert status == 'critical'

    def test_assess_status_not_synchronized(self):
        """Test assessing critical status when not synchronized."""
        data = {
            'synchronized': False,
            'stratum': 16
        }

        status = assess_status(data, 0.100, 1.000)
        assert status == 'critical'

    def test_assess_status_high_stratum(self):
        """Test assessing critical status for stratum 16."""
        data = {
            'synchronized': True,
            'system_time_offset': 0.001,
            'stratum': 16  # Unsynchronized stratum
        }

        status = assess_status(data, 0.100, 1.000)
        assert status == 'critical'

    def test_format_json(self):
        """Test JSON output format."""
        output = Output()
        output.emit({
            "source": "chrony",
            "synchronized": True,
            "reference_id": "A9FEA97B",
            "stratum": 3,
            "system_time_offset": 0.001,
            "status": "healthy"
        })

        data = output.data
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "synchronized" in parsed
        assert parsed["synchronized"] is True
        assert parsed["status"] == "healthy"
