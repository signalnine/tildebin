"""Tests for process_accounting script."""

import pytest

from boxctl.core.output import Output


class TestProcessAccounting:
    """Tests for process_accounting script."""

    def test_proc_not_available_returns_error(self, mock_context):
        """Returns 2 when /proc not available."""
        from scripts.baremetal import process_accounting

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = process_accounting.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_processes_returns_error(self, mock_context):
        """Returns 2 when no processes can be read."""
        from scripts.baremetal import process_accounting

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
        exit_code = process_accounting.run([], output, ctx)

        assert exit_code == 2

    def test_top_processes_returned(self, mock_context):
        """Returns top N processes by default."""
        from scripts.baremetal import process_accounting

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/stat': '1 (systemd) S 0 1 1 0 -1 4194560 50000 100 0 0 500 100 0 0 20 0 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/1/io': 'read_bytes: 1000000\nwrite_bytes: 500000\nrchar: 2000000\nwchar: 1000000\n',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t10000 kB\nVmSize:\t50000 kB\n',
                '/proc/100/stat': '100 (nginx) S 1 100 100 0 -1 4194560 10000 50 0 0 1000 200 0 0 20 0 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/100/io': 'read_bytes: 5000000\nwrite_bytes: 2000000\nrchar: 10000000\nwchar: 5000000\n',
                '/proc/100/status': 'Uid:\t33\t33\t33\t33\nVmRSS:\t50000 kB\nVmSize:\t100000 kB\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_accounting.run(['--top', '5'], output, ctx)

        assert exit_code == 0
        assert len(output.data['top_processes']) <= 5
        assert output.data['summary']['total_processes_scanned'] == 2

    def test_sort_by_cpu(self, mock_context):
        """Processes sorted by CPU time."""
        from scripts.baremetal import process_accounting

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/stat': '1 (low_cpu) S 0 1 1 0 -1 4194560 50000 100 0 0 100 50 0 0 20 0 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/1/io': 'read_bytes: 1000\nwrite_bytes: 500\n',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t10000 kB\n',
                '/proc/100/stat': '100 (high_cpu) S 1 100 100 0 -1 4194560 10000 50 0 0 10000 5000 0 0 20 0 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/100/io': 'read_bytes: 5000\nwrite_bytes: 2000\n',
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t50000 kB\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_accounting.run(['--sort', 'cpu'], output, ctx)

        assert exit_code == 0
        # First process should have higher CPU time
        if len(output.data['top_processes']) >= 2:
            assert output.data['top_processes'][0]['comm'] == 'high_cpu'

    def test_user_filter(self, mock_context):
        """User filter works correctly."""
        from scripts.baremetal import process_accounting

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/stat': '1 (root_proc) S 0 1 1 0 -1 4194560 50000 100 0 0 100 50 0 0 20 0 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/1/io': 'read_bytes: 1000\nwrite_bytes: 500\n',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t10000 kB\n',
                '/proc/100/stat': '100 (nobody_proc) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 0 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/100/io': 'read_bytes: 5000\nwrite_bytes: 2000\n',
                '/proc/100/status': 'Uid:\t65534\t65534\t65534\t65534\nVmRSS:\t50000 kB\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_accounting.run(['--user', 'root'], output, ctx)

        assert exit_code == 0
        # Only root processes should be in output
        assert all(p['user'] == 'root' for p in output.data['top_processes'])

    def test_warn_cpu_threshold(self, mock_context):
        """Warning threshold for CPU time."""
        from scripts.baremetal import process_accounting

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/100/stat': '100 (cpu_hog) S 1 100 100 0 -1 4194560 10000 50 0 0 500000 200000 0 0 20 0 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',  # 7000 seconds CPU
                '/proc/100/io': 'read_bytes: 5000\nwrite_bytes: 2000\n',
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t50000 kB\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        # Warn if CPU time > 60 seconds (this process has 7000s)
        exit_code = process_accounting.run(['--warn-cpu', '60'], output, ctx)

        assert exit_code == 1
        assert len(output.data['warnings']) > 0

    def test_command_filter(self, mock_context):
        """Command filter works correctly."""
        from scripts.baremetal import process_accounting

        ctx = mock_context(
            file_contents={
                '/proc': '',
                '/proc/1/stat': '1 (systemd) S 0 1 1 0 -1 4194560 50000 100 0 0 100 50 0 0 20 0 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/1/io': 'read_bytes: 1000\nwrite_bytes: 500\n',
                '/proc/1/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t10000 kB\n',
                '/proc/100/stat': '100 (nginx) S 1 100 100 0 -1 4194560 10000 50 0 0 100 50 0 0 20 0 1 0 200 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/100/io': 'read_bytes: 5000\nwrite_bytes: 2000\n',
                '/proc/100/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t50000 kB\n',
            }
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1', '/proc/100']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = process_accounting.run(['--command', 'nginx'], output, ctx)

        assert exit_code == 0
        assert all('nginx' in p['comm'].lower() for p in output.data['top_processes'])

    def test_invalid_top_returns_error(self, mock_context):
        """Returns 2 for invalid --top value."""
        from scripts.baremetal import process_accounting

        ctx = mock_context(file_contents={'/proc': ''})
        output = Output()

        exit_code = process_accounting.run(['--top', '0'], output, ctx)

        assert exit_code == 2
