"""Tests for crash_dump script."""

import pytest

from boxctl.core.output import Output


class TestCrashDump:
    """Tests for crash_dump script."""

    def test_kdump_not_installed(self, mock_context):
        """Returns 1 with warning when kdump not installed."""
        from scripts.baremetal import crash_dump

        ctx = mock_context(
            command_outputs={
                ('systemctl', 'is-enabled', 'kdump'): 'No such file or directory',
                ('systemctl', 'is-active', 'kdump'): 'inactive',
            },
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1',
            }
        )
        output = Output()

        # Mock the is-enabled to return error
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if cmd == ['systemctl', 'is-enabled', 'kdump']:
                import subprocess
                return subprocess.CompletedProcess(cmd, returncode=1, stdout='', stderr='No such file')
            if cmd == ['systemctl', 'is-active', 'kdump']:
                import subprocess
                return subprocess.CompletedProcess(cmd, returncode=1, stdout='inactive', stderr='')
            return original_run(cmd, **kwargs)
        ctx.run = mock_run

        exit_code = crash_dump.run([], output, ctx)

        assert exit_code == 1
        issues = output.data['issues']
        assert any('not installed' in i['message'].lower() for i in issues)

    def test_kdump_not_enabled(self, mock_context):
        """Returns 1 with warning when kdump not enabled."""
        from scripts.baremetal import crash_dump

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 crashkernel=auto',
            }
        )

        def mock_run(cmd, **kwargs):
            import subprocess
            if cmd == ['systemctl', 'is-enabled', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='disabled', stderr='')
            if cmd == ['systemctl', 'is-active', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=1, stdout='inactive', stderr='')
            raise KeyError(f"No mock for {cmd}")
        ctx.run = mock_run

        output = Output()
        exit_code = crash_dump.run([], output, ctx)

        assert exit_code == 1
        issues = output.data['issues']
        assert any('not enabled' in i['message'].lower() for i in issues)

    def test_crashkernel_not_reserved(self, mock_context):
        """Returns 1 with warning when crashkernel not reserved."""
        from scripts.baremetal import crash_dump

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 quiet',  # No crashkernel
            }
        )

        def mock_run(cmd, **kwargs):
            import subprocess
            if cmd == ['systemctl', 'is-enabled', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='enabled', stderr='')
            if cmd == ['systemctl', 'is-active', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='active', stderr='')
            raise KeyError(f"No mock for {cmd}")
        ctx.run = mock_run

        output = Output()
        exit_code = crash_dump.run([], output, ctx)

        assert exit_code == 1
        assert not output.data['crashkernel']['reserved']
        issues = output.data['issues']
        assert any('crashkernel' in i['message'].lower() for i in issues)

    def test_kdump_healthy_no_crashes(self, mock_context):
        """Returns 0 when kdump healthy and no crashes."""
        from scripts.baremetal import crash_dump

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 crashkernel=auto',
                '/sys/kernel/kexec_crash_size': '268435456',
                '/var/crash': '',  # Empty dir
            }
        )

        def mock_run(cmd, **kwargs):
            import subprocess
            if cmd == ['systemctl', 'is-enabled', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='enabled', stderr='')
            if cmd == ['systemctl', 'is-active', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='active', stderr='')
            raise KeyError(f"No mock for {cmd}")
        ctx.run = mock_run

        output = Output()
        exit_code = crash_dump.run([], output, ctx)

        assert exit_code == 0
        assert output.data['kdump_service']['active'] is True
        assert output.data['crashkernel']['reserved'] is True

    def test_crashes_found(self, mock_context):
        """Returns 1 when crash dumps are found."""
        from scripts.baremetal import crash_dump

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1 crashkernel=auto',
                '/sys/kernel/kexec_crash_size': '268435456',
                '/var/crash': '',
                '/var/crash/vmcore-2024-01-15': '',
            }
        )

        def mock_run(cmd, **kwargs):
            import subprocess
            if cmd == ['systemctl', 'is-enabled', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='enabled', stderr='')
            if cmd == ['systemctl', 'is-active', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='active', stderr='')
            raise KeyError(f"No mock for {cmd}")
        ctx.run = mock_run

        output = Output()
        exit_code = crash_dump.run([], output, ctx)

        assert exit_code == 1
        issues = output.data['issues']
        assert any('crash dump' in i['message'].lower() for i in issues)

    def test_crashkernel_reserved_via_sysfs(self, mock_context):
        """Detects crashkernel reservation via sysfs."""
        from scripts.baremetal import crash_dump

        ctx = mock_context(
            file_contents={
                '/proc/cmdline': 'root=/dev/sda1',  # No crashkernel in cmdline
                '/sys/kernel/kexec_crash_size': '134217728',  # But reserved via sysfs
            }
        )

        def mock_run(cmd, **kwargs):
            import subprocess
            if cmd == ['systemctl', 'is-enabled', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='enabled', stderr='')
            if cmd == ['systemctl', 'is-active', 'kdump']:
                return subprocess.CompletedProcess(cmd, returncode=0, stdout='active', stderr='')
            raise KeyError(f"No mock for {cmd}")
        ctx.run = mock_run

        output = Output()
        exit_code = crash_dump.run([], output, ctx)

        assert output.data['crashkernel']['reserved'] is True
        assert output.data['crashkernel']['actual_bytes'] == 134217728
