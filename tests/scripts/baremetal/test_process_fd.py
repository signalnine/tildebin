"""Tests for process_fd script."""

import pytest

from boxctl.core.output import Output


class TestProcessFd:
    """Tests for process_fd script."""

    def test_proc_not_available_returns_error(self, mock_context):
        """Returns 2 when /proc not available."""
        from scripts.baremetal import process_fd

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = process_fd.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_processes_returns_error(self, mock_context):
        """Returns 2 when no processes can be read."""
        from scripts.baremetal import process_fd

        ctx = mock_context(
            file_contents={
                '/proc': '',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return []
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_fd.run([], output, ctx)

        assert exit_code == 2

    def test_healthy_fd_usage(self, mock_context):
        """Returns 0 when all processes have healthy fd usage."""
        from scripts.baremetal import process_fd

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/comm': 'systemd',
                '/proc/1/limits': 'Max open files            1024                 1048576              files\n',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\n',
                '/proc/1/fd/0': '',
                '/proc/1/fd/1': '',
                '/proc/1/fd/2': '',
                '/proc/100/comm': 'nginx',
                '/proc/100/limits': 'Max open files            65536                1048576              files\n',
                '/proc/100/status': 'Uid:\t33\t33\t33\t33\n',
                '/proc/100/fd/0': '',
                '/proc/100/fd/1': '',
                '/proc/100/fd/2': '',
                '/proc/100/fd/3': '',
                '/proc/100/fd/4': '',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            if root == '/proc/1/fd' and pattern == '[0-9]*':
                return ['/proc/1/fd/0', '/proc/1/fd/1', '/proc/1/fd/2']
            if root == '/proc/100/fd' and pattern == '[0-9]*':
                return ['/proc/100/fd/0', '/proc/100/fd/1', '/proc/100/fd/2', '/proc/100/fd/3', '/proc/100/fd/4']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_fd.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert output.data['summary']['critical_count'] == 0
        assert output.data['summary']['warning_count'] == 0

    def test_warning_threshold_exceeded(self, mock_context):
        """Returns 1 when warning threshold exceeded."""
        from scripts.baremetal import process_fd

        # Create a process using 85% of its fd limit
        fd_list = [f'/proc/100/fd/{i}' for i in range(850)]
        file_contents = {
            '/proc': '',
            '/proc/100/comm': 'fd_hog',
            '/proc/100/limits': 'Max open files            1000                 1048576              files\n',
            '/proc/100/status': 'Uid:\t0\t0\t0\t0\n',
        }
        for fd in fd_list:
            file_contents[fd] = ''

        ctx = mock_context(file_contents=file_contents)
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/100']
            if root == '/proc/100/fd' and pattern == '[0-9]*':
                return fd_list
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_fd.run(['--warn', '80'], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'warning'
        assert len(output.data['warnings']) > 0

    def test_critical_threshold_exceeded(self, mock_context):
        """Returns 1 when critical threshold exceeded."""
        from scripts.baremetal import process_fd

        # Create a process using 98% of its fd limit
        fd_list = [f'/proc/100/fd/{i}' for i in range(980)]
        file_contents = {
            '/proc': '',
            '/proc/100/comm': 'fd_critical',
            '/proc/100/limits': 'Max open files            1000                 1048576              files\n',
            '/proc/100/status': 'Uid:\t0\t0\t0\t0\n',
        }
        for fd in fd_list:
            file_contents[fd] = ''

        ctx = mock_context(file_contents=file_contents)
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/100']
            if root == '/proc/100/fd' and pattern == '[0-9]*':
                return fd_list
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_fd.run(['--crit', '95'], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'critical'
        assert len(output.data['critical']) > 0

    def test_low_limit_detection(self, mock_context):
        """Detects processes with low fd limits."""
        from scripts.baremetal import process_fd

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/100/comm': 'low_limit',
                '/proc/100/limits': 'Max open files            256                  1048576              files\n',
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\n',
                '/proc/100/fd/0': '',
                '/proc/100/fd/1': '',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/100']
            if root == '/proc/100/fd' and pattern == '[0-9]*':
                return ['/proc/100/fd/0', '/proc/100/fd/1']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_fd.run(['--min-limit', '1024', '--verbose'], output, ctx)

        assert exit_code == 0  # Low limit is just informational
        assert output.data['summary']['low_limit_count'] > 0

    def test_top_consumers_returned(self, mock_context):
        """Top consumers are correctly identified."""
        from scripts.baremetal import process_fd

        # Process 100 has more fds than process 1
        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/comm': 'few_fds',
                '/proc/1/limits': 'Max open files            1024                 1048576              files\n',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\n',
                '/proc/1/fd/0': '',
                '/proc/100/comm': 'many_fds',
                '/proc/100/limits': 'Max open files            65536                1048576              files\n',
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\n',
                '/proc/100/fd/0': '',
                '/proc/100/fd/1': '',
                '/proc/100/fd/2': '',
                '/proc/100/fd/3': '',
                '/proc/100/fd/4': '',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            if root == '/proc/1/fd' and pattern == '[0-9]*':
                return ['/proc/1/fd/0']
            if root == '/proc/100/fd' and pattern == '[0-9]*':
                return ['/proc/100/fd/0', '/proc/100/fd/1', '/proc/100/fd/2', '/proc/100/fd/3', '/proc/100/fd/4']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_fd.run(['--top', '5'], output, ctx)

        assert exit_code == 0
        # many_fds should be first (more fds)
        assert output.data['top_consumers'][0]['comm'] == 'many_fds'

    def test_invalid_thresholds_returns_error(self, mock_context):
        """Returns 2 for invalid threshold configuration."""
        from scripts.baremetal import process_fd

        ctx = mock_context(file_contents={'/proc': ''})
        output = Output()

        # warn >= crit is invalid
        exit_code = process_fd.run(['--warn', '95', '--crit', '90'], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
