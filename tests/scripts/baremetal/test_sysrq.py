"""Tests for sysrq script."""

import pytest

from boxctl.core.output import Output


class TestSysrq:
    """Tests for sysrq script."""

    def test_sysrq_not_available(self, mock_context):
        """Returns exit code 2 when /proc/sys/kernel/sysrq not available."""
        from scripts.baremetal import sysrq

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = sysrq.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("sysrq" in e.lower() for e in output.errors)

    def test_sysrq_disabled(self, mock_context):
        """Returns 1 when SysRq is completely disabled."""
        from scripts.baremetal import sysrq

        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '0',
            }
        )
        output = Output()

        exit_code = sysrq.run([], output, ctx)

        assert exit_code == 1
        assert output.data['sysrq_value'] == 0
        assert output.data['enabled'] is False
        assert len(output.data['security']['warnings']) > 0

    def test_sysrq_all_enabled(self, mock_context):
        """Detects when all SysRq functions are enabled."""
        from scripts.baremetal import sysrq

        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '1',
            }
        )
        output = Output()

        exit_code = sysrq.run([], output, ctx)

        assert exit_code == 1  # Warnings expected
        assert output.data['sysrq_value'] == 1
        assert output.data['enabled'] is True
        assert output.data['all_enabled'] is True

    def test_sysrq_ubuntu_default(self, mock_context):
        """Detects Ubuntu/Debian default SysRq configuration."""
        from scripts.baremetal import sysrq

        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '176',
            }
        )
        output = Output()

        exit_code = sysrq.run([], output, ctx)

        assert output.data['sysrq_value'] == 176
        assert output.data['enabled'] is True
        assert 'Ubuntu' in output.data['config_description'] or 'Debian' in output.data['config_description']

    def test_sysrq_custom_bitmask(self, mock_context):
        """Decodes custom bitmask values."""
        from scripts.baremetal import sysrq

        # 16 + 32 + 128 = 176 (sync + remount + reboot)
        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '176',
            }
        )
        output = Output()

        exit_code = sysrq.run([], output, ctx)

        func_names = [f['name'] for f in output.data['functions']]
        assert 'sync' in func_names
        assert 'remount_ro' in func_names
        assert 'reboot' in func_names

    def test_expected_value_match(self, mock_context):
        """Returns 0 when expected value matches."""
        from scripts.baremetal import sysrq

        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '176',
            }
        )
        output = Output()

        # Expect 176, without checking other warnings
        exit_code = sysrq.run(['--expected', '176'], output, ctx)

        assert output.data['matches_expected'] is True

    def test_expected_value_mismatch(self, mock_context):
        """Returns 1 when expected value does not match."""
        from scripts.baremetal import sysrq

        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '176',
            }
        )
        output = Output()

        exit_code = sysrq.run(['--expected', '1'], output, ctx)

        assert exit_code == 1
        assert output.data['matches_expected'] is False
        assert output.data['expected_value'] == 1

    def test_invalid_expected_value(self, mock_context):
        """Returns 2 for invalid expected value."""
        from scripts.baremetal import sysrq

        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '176',
            }
        )
        output = Output()

        exit_code = sysrq.run(['--expected', '999'], output, ctx)

        assert exit_code == 2

    def test_require_emergency_functions(self, mock_context):
        """--require-emergency checks for emergency functions."""
        from scripts.baremetal import sysrq

        # Value 8 only enables debugging, not emergency functions
        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '8',
            }
        )
        output = Output()

        exit_code = sysrq.run(['--require-emergency'], output, ctx)

        assert exit_code == 1
        assert any('missing' in i.lower() for i in output.data['security']['issues'])

    def test_require_emergency_satisfied(self, mock_context):
        """--require-emergency passes when emergency functions present."""
        from scripts.baremetal import sysrq

        # 176 = sync + remount + reboot (emergency functions)
        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '176',
            }
        )
        output = Output()

        exit_code = sysrq.run(['--require-emergency'], output, ctx)

        # Should not have missing emergency functions issue
        missing_issues = [i for i in output.data['security']['issues'] if 'missing' in i.lower()]
        assert len(missing_issues) == 0

    def test_verbose_output(self, mock_context):
        """--verbose flag works."""
        from scripts.baremetal import sysrq

        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '176',
            }
        )
        output = Output()

        exit_code = sysrq.run(['--verbose'], output, ctx)

        assert 'functions' in output.data
        assert len(output.data['functions']) > 0

    def test_security_analysis_high_severity(self, mock_context):
        """Detects high severity functions."""
        from scripts.baremetal import sysrq

        # Value 1 enables all including high severity
        ctx = mock_context(
            file_contents={
                '/proc/sys/kernel/sysrq': '1',
            }
        )
        output = Output()

        exit_code = sysrq.run([], output, ctx)

        assert output.data['summary']['high_severity'] > 0
