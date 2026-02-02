#!/usr/bin/env python3
"""Tests for scripts/baremetal/gpu_health.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.gpu_health import run, determine_gpu_status


class TestGpuHealth:
    """Tests for gpu_health script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = Context()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_determine_status_healthy(self):
        """Test determining healthy GPU status."""
        gpu = {
            'temperature': 60,
            'ecc_corrected': 0,
            'ecc_uncorrected': 0,
            'memory_total': 8192,
            'memory_used': 4096,
            'power_draw': 100.0,
            'power_limit': 250.0,
            'fan_speed': 50
        }

        status = determine_gpu_status(gpu)
        assert status == 'healthy'

    def test_determine_status_high_temp(self):
        """Test warning for high temperature."""
        gpu = {
            'temperature': 85,  # 80-90 is warning
            'ecc_corrected': 0,
            'ecc_uncorrected': 0,
            'memory_total': 8192,
            'memory_used': 4096,
            'power_draw': 100.0,
            'power_limit': 250.0,
            'fan_speed': 80
        }

        status = determine_gpu_status(gpu)
        assert status == 'warning'

    def test_determine_status_critical_temp(self):
        """Test critical for very high temperature."""
        gpu = {
            'temperature': 95,  # >= 90 is critical
            'ecc_corrected': 0,
            'ecc_uncorrected': 0,
            'memory_total': 8192,
            'memory_used': 4096,
            'power_draw': 100.0,
            'power_limit': 250.0,
            'fan_speed': 100
        }

        status = determine_gpu_status(gpu)
        assert status == 'critical'

    def test_determine_status_ecc_uncorrected(self):
        """Test critical for uncorrected ECC errors."""
        gpu = {
            'temperature': 60,
            'ecc_corrected': 0,
            'ecc_uncorrected': 1,  # Any uncorrected is critical
            'memory_total': 8192,
            'memory_used': 4096,
            'power_draw': 100.0,
            'power_limit': 250.0,
            'fan_speed': 50
        }

        status = determine_gpu_status(gpu)
        assert status == 'critical'

    def test_determine_status_high_ecc_corrected(self):
        """Test warning for many corrected ECC errors."""
        gpu = {
            'temperature': 60,
            'ecc_corrected': 150,  # > 100 is warning
            'ecc_uncorrected': 0,
            'memory_total': 8192,
            'memory_used': 4096,
            'power_draw': 100.0,
            'power_limit': 250.0,
            'fan_speed': 50
        }

        status = determine_gpu_status(gpu)
        assert status == 'warning'

    def test_determine_status_high_memory(self):
        """Test warning for high memory usage."""
        gpu = {
            'temperature': 60,
            'ecc_corrected': 0,
            'ecc_uncorrected': 0,
            'memory_total': 8192,
            'memory_used': 7900,  # > 95% usage
            'power_draw': 100.0,
            'power_limit': 250.0,
            'fan_speed': 50
        }

        status = determine_gpu_status(gpu)
        assert status == 'warning'

    def test_determine_status_high_power(self):
        """Test warning for high power consumption."""
        gpu = {
            'temperature': 60,
            'ecc_corrected': 0,
            'ecc_uncorrected': 0,
            'memory_total': 8192,
            'memory_used': 4096,
            'power_draw': 240.0,  # > 95% of limit
            'power_limit': 250.0,
            'fan_speed': 50
        }

        status = determine_gpu_status(gpu)
        assert status == 'warning'

    def test_determine_status_fan_stopped(self):
        """Test warning for stopped fan with hot GPU."""
        gpu = {
            'temperature': 70,  # Hot GPU
            'ecc_corrected': 0,
            'ecc_uncorrected': 0,
            'memory_total': 8192,
            'memory_used': 4096,
            'power_draw': 100.0,
            'power_limit': 250.0,
            'fan_speed': 0  # Fan not spinning
        }

        status = determine_gpu_status(gpu)
        assert status == 'warning'

    def test_determine_status_none_values(self):
        """Test handling of None values."""
        gpu = {
            'temperature': None,
            'ecc_corrected': None,
            'ecc_uncorrected': None,
            'memory_total': None,
            'memory_used': None,
            'power_draw': None,
            'power_limit': None,
            'fan_speed': None
        }

        status = determine_gpu_status(gpu)
        assert status == 'healthy'  # No data means no detected issues

    def test_format_json(self):
        """Test JSON output format."""
        output = Output()
        output.emit({
            "gpus": [{
                "index": 0,
                "name": "NVIDIA Tesla V100",
                "temperature": 60,
                "status": "healthy"
            }]
        })

        data = output.data
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "gpus" in parsed
        assert len(parsed["gpus"]) == 1
        assert parsed["gpus"][0]["status"] == "healthy"
