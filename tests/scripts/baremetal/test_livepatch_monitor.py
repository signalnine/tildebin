"""Tests for livepatch_monitor script."""

import pytest

from boxctl.core.output import Output


class TestLivepatchMonitor:
    """Tests for livepatch_monitor script."""

    def test_no_livepatch_support_returns_healthy(self, mock_context):
        """Returns 0 when no livepatch support is present."""
        from scripts.baremetal import livepatch_monitor

        ctx = mock_context(
            tools_available=['uname'],
            command_outputs={
                ('uname', '-r'): '5.15.0-generic\n',
                ('uname', '-v'): '#1 SMP\n',
            },
            file_contents={}
        )
        output = Output()

        exit_code = livepatch_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data['support']['livepatch_enabled'] is False

    def test_livepatch_enabled_no_patches(self, mock_context):
        """Returns 0 when livepatch enabled but no patches loaded."""
        from scripts.baremetal import livepatch_monitor

        ctx = mock_context(
            tools_available=['uname'],
            command_outputs={
                ('uname', '-r'): '5.15.0-generic\n',
                ('uname', '-v'): '#1 SMP\n',
            },
            file_contents={
                '/sys/kernel/livepatch': '',  # Directory exists
            }
        )
        output = Output()

        exit_code = livepatch_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data['support']['livepatch_enabled'] is True

    def test_sysfs_patch_enabled(self, mock_context):
        """Returns 0 when sysfs patch is enabled."""
        from scripts.baremetal import livepatch_monitor

        ctx = mock_context(
            tools_available=['uname'],
            command_outputs={
                ('uname', '-r'): '5.15.0-generic\n',
                ('uname', '-v'): '#1 SMP\n',
            },
            file_contents={
                '/sys/kernel/livepatch': '',
                '/sys/kernel/livepatch/test_patch': '',
                '/sys/kernel/livepatch/test_patch/enabled': '1\n',
                '/sys/kernel/livepatch/test_patch/transition': '0\n',
            }
        )
        output = Output()

        exit_code = livepatch_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['enabled_patches'] == 1

    def test_sysfs_patch_disabled_returns_warning(self, mock_context):
        """Returns 1 when sysfs patch is disabled."""
        from scripts.baremetal import livepatch_monitor

        ctx = mock_context(
            tools_available=['uname'],
            command_outputs={
                ('uname', '-r'): '5.15.0-generic\n',
                ('uname', '-v'): '#1 SMP\n',
            },
            file_contents={
                '/sys/kernel/livepatch': '',
                '/sys/kernel/livepatch/security_patch': '',
                '/sys/kernel/livepatch/security_patch/enabled': '0\n',
                '/sys/kernel/livepatch/security_patch/transition': '0\n',
            }
        )
        output = Output()

        exit_code = livepatch_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['disabled_patches'] == 1

    def test_kpatch_available(self, mock_context):
        """Detects kpatch when available."""
        from scripts.baremetal import livepatch_monitor

        ctx = mock_context(
            tools_available=['uname', 'kpatch'],
            command_outputs={
                ('uname', '-r'): '5.15.0-generic\n',
                ('uname', '-v'): '#1 SMP\n',
                ('kpatch', 'list'): 'Loaded patch modules:\nkpatch_cve_2023_1234 [enabled]\n',
            },
            file_contents={}
        )
        output = Output()

        exit_code = livepatch_monitor.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'kpatch' in output.data['summary']['systems']

    def test_canonical_livepatch_disabled(self, mock_context):
        """Returns warning when Canonical Livepatch is installed but disabled."""
        from scripts.baremetal import livepatch_monitor

        import json
        livepatch_status = json.dumps({
            'Status': 'disabled',
            'Running': False,
            'MachineToken': '',
        })

        ctx = mock_context(
            tools_available=['uname', 'canonical-livepatch'],
            command_outputs={
                ('uname', '-r'): '5.15.0-generic\n',
                ('uname', '-v'): '#1 SMP\n',
                ('canonical-livepatch', 'status', '--format', 'json'): livepatch_status,
            },
            file_contents={}
        )
        output = Output()

        exit_code = livepatch_monitor.run(['--verbose'], output, ctx)

        assert exit_code == 1
        assert 'canonical-livepatch' in output.data['summary']['systems']
