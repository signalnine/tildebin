"""Tests for process_priority script."""

import pytest

from boxctl.core.output import Output


class TestProcessPriority:
    """Tests for process_priority script."""

    def test_proc_not_available_returns_error(self, mock_context):
        """Returns 2 when /proc not available."""
        from scripts.baremetal import process_priority

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = process_priority.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_priority_issues(self, mock_context):
        """Returns 0 when no priority issues detected."""
        from scripts.baremetal import process_priority

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/comm': 'systemd',
                '/proc/1/stat': '1 (systemd) S 0 1 1 0 -1 4194560 50000 100 0 0 100 50 0 0 20 0 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\n',
                '/proc/100/comm': 'nginx',
                '/proc/100/stat': '100 (nginx) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 0 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/100/status': 'Uid:\t33\t33\t33\t33\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_priority.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['elevated_nice_count'] == 0

    def test_elevated_priority_detected(self, mock_context):
        """Returns 1 when elevated priority detected."""
        from scripts.baremetal import process_priority

        # Nice value is at field 19 (0-indexed: 18) after the closing paren
        # Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice ...
        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/100/comm': 'important',
                '/proc/100/stat': '100 (important) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 -15 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',  # nice = -15
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_priority.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['elevated_nice_count'] > 0

    def test_degraded_priority_detected(self, mock_context):
        """Degraded priority is informational, returns 0."""
        from scripts.baremetal import process_priority

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/100/comm': 'background',
                '/proc/100/stat': '100 (background) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 15 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',  # nice = 15
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_priority.run([], output, ctx)

        assert exit_code == 0  # Degraded is informational
        assert output.data['summary']['degraded_nice_count'] > 0

    def test_include_all_processes(self, mock_context):
        """--all flag includes processes without issues."""
        from scripts.baremetal import process_priority

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/comm': 'normal',
                '/proc/1/stat': '1 (normal) S 0 1 1 0 -1 4194560 50000 100 0 0 100 50 0 0 20 0 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',  # nice = 0
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()

        # Without --all, normal process would be filtered out
        exit_code = process_priority.run([], output, ctx)
        assert len(output.data['processes']) == 0

        # With --all, normal process should be included
        output2 = Output()
        exit_code2 = process_priority.run(['--all'], output2, ctx)
        assert exit_code2 == 0
        assert len(output2.data['processes']) == 1

    def test_user_filter(self, mock_context):
        """User filter works correctly."""
        from scripts.baremetal import process_priority

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/comm': 'root_proc',
                '/proc/1/stat': '1 (root_proc) S 0 1 1 0 -1 4194560 50000 100 0 0 100 50 0 0 20 -10 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\n',
                '/proc/100/comm': 'user_proc',
                '/proc/100/stat': '100 (user_proc) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 -10 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/100/status': 'Uid:\t1000\t1000\t1000\t1000\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        # Use --all to include the process (it has elevated priority)
        exit_code = process_priority.run(['--user', 'root', '--all'], output, ctx)

        # Only root's process should be in output
        assert all(p['user'] == 'root' for p in output.data['processes'])

    def test_comm_filter(self, mock_context):
        """Command filter works correctly."""
        from scripts.baremetal import process_priority

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/comm': 'systemd',
                '/proc/1/stat': '1 (systemd) S 0 1 1 0 -1 4194560 50000 100 0 0 100 50 0 0 20 -10 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\n',
                '/proc/100/comm': 'nginx',
                '/proc/100/stat': '100 (nginx) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 -10 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/100/status': 'Uid:\t33\t33\t33\t33\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_priority.run(['--comm', 'nginx'], output, ctx)

        # Only nginx should be in output
        assert all('nginx' in p['comm'].lower() for p in output.data['processes'])

    def test_custom_thresholds(self, mock_context):
        """Custom nice thresholds are respected."""
        from scripts.baremetal import process_priority

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/100/comm': 'priority_proc',
                '/proc/100/stat': '100 (priority_proc) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 -3 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',  # nice = -3
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        # With default threshold (-5), nice=-3 is not elevated
        exit_code = process_priority.run([], output, ctx)
        assert exit_code == 0

        # With custom threshold (-2), nice=-3 is elevated
        output2 = Output()
        exit_code2 = process_priority.run(['--nice-elevated', '-2'], output2, ctx)
        assert exit_code2 == 1
        assert output2.data['summary']['elevated_nice_count'] > 0
