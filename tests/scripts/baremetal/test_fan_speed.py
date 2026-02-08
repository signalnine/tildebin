"""Tests for fan_speed script."""

import json
import pytest

from boxctl.core.output import Output


class TestFanSpeed:
    """Tests for fan_speed script."""

    def test_no_hwmon_dir(self, mock_context):
        """Returns exit code 2 when no hwmon entries exist."""
        from scripts.baremetal.fan_speed import run

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('hwmon' in e.lower() for e in output.errors)

    def test_no_fan_sensors(self, mock_context):
        """Returns exit code 0 with INFO when hwmon exists but no fan files."""
        from scripts.baremetal.fan_speed import run

        # hwmon0 exists (has a name file) but no fan*_input files
        ctx = mock_context(file_contents={
            '/sys/class/hwmon/hwmon0/name': 'coretemp',
            '/sys/class/hwmon/hwmon0/temp1_input': '45000',
        })
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data['fans'] == []
        assert 'No fan sensors found' in output.summary

    def test_all_fans_healthy(self, mock_context):
        """Returns exit code 0 when all fans are above min RPM."""
        from scripts.baremetal.fan_speed import run

        ctx = mock_context(file_contents={
            '/sys/class/hwmon/hwmon0/name': 'nct6795',
            '/sys/class/hwmon/hwmon0/fan1_input': '1200',
            '/sys/class/hwmon/hwmon0/fan1_min': '600',
            '/sys/class/hwmon/hwmon0/fan1_label': 'CPU Fan',
            '/sys/class/hwmon/hwmon0/fan2_input': '900',
            '/sys/class/hwmon/hwmon0/fan2_min': '600',
            '/sys/class/hwmon/hwmon0/fan2_label': 'System Fan',
        })
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total'] == 2
        assert output.data['summary']['ok'] == 2
        assert output.data['summary']['warning'] == 0
        assert output.data['summary']['critical'] == 0

    def test_fan_stopped(self, mock_context):
        """Returns exit code 1 CRITICAL when one fan at 0 RPM and another spinning."""
        from scripts.baremetal.fan_speed import run

        ctx = mock_context(file_contents={
            '/sys/class/hwmon/hwmon0/name': 'nct6795',
            '/sys/class/hwmon/hwmon0/fan1_input': '1200',
            '/sys/class/hwmon/hwmon0/fan1_min': '600',
            '/sys/class/hwmon/hwmon0/fan1_label': 'CPU Fan',
            '/sys/class/hwmon/hwmon0/fan2_input': '0',
            '/sys/class/hwmon/hwmon0/fan2_min': '600',
            '/sys/class/hwmon/hwmon0/fan2_label': 'System Fan',
        })
        output = Output()

        exit_code = run(['--verbose'], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['critical'] > 0

        # Find the stopped fan
        stopped_fans = [
            f for f in output.data['fans']
            if f.get('status') == 'CRITICAL'
        ]
        assert len(stopped_fans) == 1
        assert stopped_fans[0]['rpm'] == 0

    def test_fan_below_min(self, mock_context):
        """Returns exit code 1 WARNING when fan RPM is below fan_min threshold."""
        from scripts.baremetal.fan_speed import run

        ctx = mock_context(file_contents={
            '/sys/class/hwmon/hwmon0/name': 'nct6795',
            '/sys/class/hwmon/hwmon0/fan1_input': '1200',
            '/sys/class/hwmon/hwmon0/fan1_min': '600',
            '/sys/class/hwmon/hwmon0/fan1_label': 'CPU Fan',
            '/sys/class/hwmon/hwmon0/fan2_input': '400',
            '/sys/class/hwmon/hwmon0/fan2_min': '600',
            '/sys/class/hwmon/hwmon0/fan2_label': 'System Fan',
        })
        output = Output()

        exit_code = run(['--verbose'], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['warning'] > 0

        # Find the slow fan
        warning_fans = [
            f for f in output.data['fans']
            if f.get('status') == 'WARNING'
        ]
        assert len(warning_fans) == 1
        assert warning_fans[0]['rpm'] == 400

    def test_json_output(self, mock_context):
        """Verify fans list is present in output data."""
        from scripts.baremetal.fan_speed import run

        ctx = mock_context(file_contents={
            '/sys/class/hwmon/hwmon0/name': 'nct6795',
            '/sys/class/hwmon/hwmon0/fan1_input': '1200',
            '/sys/class/hwmon/hwmon0/fan1_min': '600',
            '/sys/class/hwmon/hwmon0/fan1_label': 'CPU Fan',
            '/sys/class/hwmon/hwmon0/fan2_input': '900',
            '/sys/class/hwmon/hwmon0/fan2_min': '600',
            '/sys/class/hwmon/hwmon0/fan2_label': 'System Fan',
        })
        output = Output()

        exit_code = run(['--format', 'json'], output, ctx)

        assert exit_code == 0
        assert 'fans' in output.data
        assert 'summary' in output.data
        assert isinstance(output.data['fans'], list)
        assert len(output.data['fans']) == 2

        # Verify fan structure
        fan = output.data['fans'][0]
        assert 'fan_id' in fan
        assert 'chip' in fan
        assert 'rpm' in fan
        assert 'status' in fan

        # Verify JSON serializable
        json_str = json.dumps(output.data)
        parsed = json.loads(json_str)
        assert 'fans' in parsed
