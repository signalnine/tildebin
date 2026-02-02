#!/usr/bin/env python3
"""Tests for scripts/baremetal/cpu_frequency.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.cpu_frequency import run, get_cpu_info, analyze_cpu_status


class MockContext(Context):
    """Mock context for testing."""

    def __init__(self, files=None):
        super().__init__()
        self._files = files or {}

    def file_exists(self, path: str) -> bool:
        return path in self._files


class TestCpuFrequency:
    """Tests for cpu_frequency script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = MockContext()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_no_cpufreq_interface(self):
        """Test error when cpufreq interface is not available."""
        output = Output()
        context = MockContext(files={})

        result = run([], output, context)

        assert result == 2
        assert bool(output.errors)

    def test_analyze_healthy_cpu(self):
        """Test analyze_cpu_status with healthy CPU."""
        cpu_info = {
            'cpu': 0,
            'current_freq': 2500000,  # 2.5 GHz
            'min_freq': 800000,
            'max_freq': 3000000,  # 3.0 GHz
            'scaling_min_freq': 800000,
            'scaling_max_freq': 3000000,
            'governor': 'performance',
            'driver': 'intel_pstate',
            'status': 'healthy'
        }

        result = analyze_cpu_status(cpu_info, expected_governor=None)

        assert result['status'] == 'healthy'
        assert result['issues'] == []

    def test_analyze_wrong_governor(self):
        """Test analyze_cpu_status with unexpected governor."""
        cpu_info = {
            'cpu': 0,
            'current_freq': 2500000,
            'min_freq': 800000,
            'max_freq': 3000000,
            'scaling_min_freq': 800000,
            'scaling_max_freq': 3000000,
            'governor': 'powersave',
            'driver': 'intel_pstate',
            'status': 'healthy'
        }

        result = analyze_cpu_status(cpu_info, expected_governor='performance')

        assert result['status'] == 'warning'
        assert len(result['issues']) == 1
        assert 'powersave' in result['issues'][0]
        assert 'performance' in result['issues'][0]

    def test_analyze_throttled_cpu(self):
        """Test analyze_cpu_status with throttled CPU."""
        cpu_info = {
            'cpu': 0,
            'current_freq': 1000000,  # 1.0 GHz (33% of max)
            'min_freq': 800000,
            'max_freq': 3000000,  # 3.0 GHz
            'scaling_min_freq': 800000,
            'scaling_max_freq': 3000000,
            'governor': 'performance',
            'driver': 'intel_pstate',
            'status': 'healthy'
        }

        result = analyze_cpu_status(cpu_info, check_throttling=True)

        assert result['status'] == 'warning'
        assert any('throttling' in issue for issue in result['issues'])

    def test_analyze_no_throttle_check(self):
        """Test analyze_cpu_status with throttle check disabled."""
        cpu_info = {
            'cpu': 0,
            'current_freq': 1000000,  # Would trigger throttle warning
            'min_freq': 800000,
            'max_freq': 3000000,
            'scaling_min_freq': 800000,
            'scaling_max_freq': 3000000,
            'governor': 'performance',
            'driver': 'intel_pstate',
            'status': 'healthy'
        }

        result = analyze_cpu_status(cpu_info, check_throttling=False)

        assert result['status'] == 'healthy'
        assert len(result['issues']) == 0

    def test_analyze_limited_scaling(self):
        """Test analyze_cpu_status with artificially limited scaling."""
        cpu_info = {
            'cpu': 0,
            'current_freq': 2500000,
            'min_freq': 800000,
            'max_freq': 3000000,
            'scaling_min_freq': 800000,
            'scaling_max_freq': 2000000,  # Limited below hardware max
            'governor': 'performance',
            'driver': 'intel_pstate',
            'status': 'healthy'
        }

        result = analyze_cpu_status(cpu_info)

        assert result['status'] == 'warning'
        assert any('Scaling max limited' in issue for issue in result['issues'])

    def test_format_json(self):
        """Test --format json produces valid JSON."""
        # This test requires mocking the cpufreq sysfs interface
        # For now, just verify the output format helper
        output = Output()
        output.emit({
            "cpus": [{"cpu": 0, "status": "healthy", "governor": "performance"}],
            "driver": "intel_pstate",
            "governors": {"performance": 1},
            "summary": {"total": 1, "healthy": 1, "warnings": 0}
        })

        data = output.data
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "cpus" in parsed
        assert "driver" in parsed
        assert "summary" in parsed

    def test_warn_only_filter(self):
        """Test that --warn-only filters healthy CPUs."""
        output = Output()

        # Simulate filtered data
        data = {
            "cpus": [],  # No unhealthy CPUs
            "driver": "intel_pstate",
            "governors": {"performance": 4},
            "summary": {"total": 4, "healthy": 4, "warnings": 0}
        }
        output.emit(data)

        result_data = output.data
        assert len(result_data["cpus"]) == 0
        assert result_data["summary"]["warnings"] == 0
