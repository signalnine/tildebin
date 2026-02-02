"""Tests for loadavg_analyzer script."""

import pytest

from boxctl.core.output import Output


class TestLoadavgAnalyzer:
    """Tests for loadavg_analyzer script."""

    def test_missing_proc_loadavg_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/loadavg not available."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = loadavg_analyzer.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_normal_load_returns_healthy(self, mock_context):
        """Returns 0 when load is within normal limits."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '0.50 0.45 0.40 1/200 12345\n',
                '/proc/uptime': '86400.00 172800.00\n',
            },
            env={'cpu_count': '4'}
        )
        output = Output()

        exit_code = loadavg_analyzer.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert output.data['load']['raw']['1min'] == 0.50

    def test_high_load_returns_warning(self, mock_context):
        """Returns 1 when load exceeds warning threshold."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '5.00 4.50 4.00 5/200 12345\n',
                '/proc/uptime': '86400.00 172800.00\n',
            },
            env={'cpu_count': '4'}  # 5.0/4 = 1.25 per CPU
        )
        output = Output()

        exit_code = loadavg_analyzer.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'warning'
        assert len(output.data['issues']) > 0

    def test_critical_load(self, mock_context):
        """Returns 1 with critical status when load is very high."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '10.00 9.50 9.00 10/200 12345\n',
                '/proc/uptime': '86400.00 172800.00\n',
            },
            env={'cpu_count': '4'}  # 10.0/4 = 2.5 per CPU
        )
        output = Output()

        exit_code = loadavg_analyzer.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'critical'

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds are respected."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '2.00 1.80 1.60 2/200 12345\n',
                '/proc/uptime': '86400.00 172800.00\n',
            },
            env={'cpu_count': '4'}  # 2.0/4 = 0.5 per CPU
        )
        output = Output()

        # With default thresholds (warn=1.0), this should be OK
        exit_code = loadavg_analyzer.run([], output, ctx)
        assert exit_code == 0

        # With lower threshold, should be warning
        output = Output()
        exit_code = loadavg_analyzer.run(['--warn', '0.4'], output, ctx)
        assert exit_code == 1

    def test_trend_detection_increasing(self, mock_context):
        """Detects increasing load trend."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '3.00 1.50 1.00 3/200 12345\n',  # 1min much higher than 5min
                '/proc/uptime': '86400.00 172800.00\n',
            },
            env={'cpu_count': '4'}
        )
        output = Output()

        exit_code = loadavg_analyzer.run([], output, ctx)

        assert output.data['trend'] == 'increasing'

    def test_trend_detection_decreasing(self, mock_context):
        """Detects decreasing load trend."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '0.50 2.00 3.00 1/200 12345\n',  # 1min much lower than 5min
                '/proc/uptime': '86400.00 172800.00\n',
            },
            env={'cpu_count': '4'}
        )
        output = Output()

        exit_code = loadavg_analyzer.run([], output, ctx)

        assert output.data['trend'] == 'decreasing'

    def test_invalid_warn_threshold(self, mock_context):
        """Returns error for invalid --warn threshold."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '0.50 0.45 0.40 1/200 12345\n',
            },
            env={'cpu_count': '4'}
        )
        output = Output()

        exit_code = loadavg_analyzer.run(['--warn', '-1'], output, ctx)

        assert exit_code == 2

    def test_crit_less_than_warn_error(self, mock_context):
        """Returns error when --crit < --warn."""
        from scripts.baremetal import loadavg_analyzer

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/loadavg': '0.50 0.45 0.40 1/200 12345\n',
            },
            env={'cpu_count': '4'}
        )
        output = Output()

        exit_code = loadavg_analyzer.run(['--warn', '2.0', '--crit', '1.0'], output, ctx)

        assert exit_code == 2
