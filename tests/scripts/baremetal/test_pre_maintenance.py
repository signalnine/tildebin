"""Tests for pre_maintenance script."""

import pytest

from boxctl.core.output import Output


class TestPreMaintenance:
    """Tests for pre_maintenance script."""

    def test_proc_not_available_returns_error(self, mock_context):
        """Returns 2 when /proc not available."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = pre_maintenance.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_all_checks_pass(self, mock_context):
        """Returns 0 when all checks pass."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'): '',
            },
            file_contents={
                '/proc': '',  # directory exists
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
SwapTotal:       4000000 kB
SwapFree:        4000000 kB
Dirty:             10000 kB
""",
                '/proc/loadavg': '0.5 0.7 0.9 1/200 12345',
                '/proc/sys/kernel/tainted': '0',
            },
            env={'cpu_count': '4'}
        )
        # Mock glob to return empty for process scanning
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return []
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = pre_maintenance.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['safe_to_proceed'] is True

    def test_dstate_processes_detected(self, mock_context):
        """Returns 1 when D-state processes detected."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'): '',
            },
            file_contents={
                '/proc': '',
                '/proc/1234/stat': '1234 (stuck_process) D 1 1234 1234 0 -1 4194560 100 0 0 0 10 5 0 0 20 0 1 0 100 10000000 500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0',
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
SwapTotal:       4000000 kB
SwapFree:        4000000 kB
Dirty:             10000 kB
""",
                '/proc/loadavg': '0.5 0.7 0.9 1/200 12345',
                '/proc/sys/kernel/tainted': '0',
            },
            env={'cpu_count': '4'}
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return ['/proc/1234']
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = pre_maintenance.run([], output, ctx)

        assert exit_code == 1
        dstate_check = next((c for c in output.data['checks'] if c['name'] == 'D-State Processes'), None)
        assert dstate_check is not None
        assert dstate_check['status'] == 'WARNING'

    def test_high_memory_pressure_detected(self, mock_context):
        """Returns 1 when memory pressure is critical."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'): '',
            },
            file_contents={
                '/proc': '',
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:          200000 kB
MemAvailable:     500000 kB
SwapTotal:       4000000 kB
SwapFree:         100000 kB
Dirty:             10000 kB
""",
                '/proc/loadavg': '0.5 0.7 0.9 1/200 12345',
                '/proc/sys/kernel/tainted': '0',
            },
            env={'cpu_count': '4'}
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return []
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = pre_maintenance.run([], output, ctx)

        assert exit_code == 1
        mem_check = next((c for c in output.data['checks'] if c['name'] == 'Memory Pressure'), None)
        assert mem_check is not None
        assert mem_check['status'] in ['WARNING', 'CRITICAL']

    def test_high_load_detected(self, mock_context):
        """Returns 1 when system load is too high."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'): '',
            },
            file_contents={
                '/proc': '',
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
SwapTotal:       4000000 kB
SwapFree:        4000000 kB
Dirty:             10000 kB
""",
                '/proc/loadavg': '25.0 20.0 15.0 50/200 12345',  # Very high load
                '/proc/sys/kernel/tainted': '0',
            },
            env={'cpu_count': '4'}
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return []
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = pre_maintenance.run([], output, ctx)

        assert exit_code == 1
        load_check = next((c for c in output.data['checks'] if c['name'] == 'System Load'), None)
        assert load_check is not None
        assert load_check['status'] in ['WARNING', 'CRITICAL']

    def test_failed_systemd_units_detected(self, mock_context):
        """Returns 1 when failed systemd units detected."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'): 'nginx.service loaded failed failed\npostgresql.service loaded failed failed\n',
            },
            file_contents={
                '/proc': '',
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
SwapTotal:       4000000 kB
SwapFree:        4000000 kB
Dirty:             10000 kB
""",
                '/proc/loadavg': '0.5 0.7 0.9 1/200 12345',
                '/proc/sys/kernel/tainted': '0',
            },
            env={'cpu_count': '4'}
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return []
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = pre_maintenance.run([], output, ctx)

        assert exit_code == 1
        systemd_check = next((c for c in output.data['checks'] if c['name'] == 'Systemd Units'), None)
        assert systemd_check is not None
        assert systemd_check['status'] == 'WARNING'

    def test_kernel_taint_detected(self, mock_context):
        """Returns 1 when kernel is tainted with concerning flags."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'): '',
            },
            file_contents={
                '/proc': '',
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
SwapTotal:       4000000 kB
SwapFree:        4000000 kB
Dirty:             10000 kB
""",
                '/proc/loadavg': '0.5 0.7 0.9 1/200 12345',
                '/proc/sys/kernel/tainted': '128',  # OOPS flag
            },
            env={'cpu_count': '4'}
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return []
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = pre_maintenance.run([], output, ctx)

        assert exit_code == 1
        taint_check = next((c for c in output.data['checks'] if c['name'] == 'Kernel Taint'), None)
        assert taint_check is not None
        assert taint_check['status'] in ['WARNING', 'CRITICAL']

    def test_verbose_includes_details(self, mock_context):
        """Verbose mode includes check details."""
        from scripts.baremetal import pre_maintenance

        ctx = mock_context(
            tools_available=['systemctl'],
            command_outputs={
                ('systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'): '',
            },
            file_contents={
                '/proc': '',
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
SwapTotal:       4000000 kB
SwapFree:        4000000 kB
Dirty:             10000 kB
""",
                '/proc/loadavg': '0.5 0.7 0.9 1/200 12345',
                '/proc/sys/kernel/tainted': '0',
            },
            env={'cpu_count': '4'}
        )
        original_glob = ctx.glob
        def mock_glob(pattern, root='.'):
            if root == '/proc' and pattern == '[0-9]*':
                return []
            return original_glob(pattern, root)
        ctx.glob = mock_glob

        output = Output()
        exit_code = pre_maintenance.run(['--verbose'], output, ctx)

        assert exit_code == 0
        # Verbose mode should include details field
        assert all('details' in c for c in output.data['checks'])
