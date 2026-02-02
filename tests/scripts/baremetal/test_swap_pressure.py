"""Tests for swap_pressure script."""

import pytest

from boxctl.core.output import Output


MEMINFO_HEALTHY = """MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   10240000 kB
Buffers:          512000 kB
Cached:          2048000 kB
SwapCached:        10000 kB
SwapTotal:       8192000 kB
SwapFree:        8000000 kB
"""

MEMINFO_HIGH_SWAP = """MemTotal:       16384000 kB
MemFree:         1024000 kB
MemAvailable:    2048000 kB
Buffers:          256000 kB
Cached:          1024000 kB
SwapCached:       100000 kB
SwapTotal:       8192000 kB
SwapFree:        2048000 kB
"""

MEMINFO_CRITICAL_SWAP = """MemTotal:       16384000 kB
MemFree:          512000 kB
MemAvailable:    1024000 kB
Buffers:          128000 kB
Cached:           512000 kB
SwapCached:        50000 kB
SwapTotal:       8192000 kB
SwapFree:         819200 kB
"""

MEMINFO_NO_SWAP = """MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   10240000 kB
Buffers:          512000 kB
Cached:          2048000 kB
SwapTotal:              0 kB
SwapFree:               0 kB
"""

VMSTAT_NORMAL = """pswpin 1000
pswpout 500
pgpgin 100000
pgpgout 50000
"""

VMSTAT_ACTIVE_SWAP = """pswpin 10000
pswpout 15000
pgpgin 200000
pgpgout 100000
"""


class TestSwapPressure:
    """Tests for swap_pressure script."""

    def test_no_meminfo_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/meminfo not available."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = swap_pressure.run(['--no-sample'], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_swap(self, mock_context):
        """Returns 0 when swap usage is healthy."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_HEALTHY,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample'], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert output.data['swap']['percent_used'] < 50

    def test_high_swap_warning(self, mock_context):
        """Returns 1 when swap usage exceeds warning threshold."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_HIGH_SWAP,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample'], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'warning'
        assert output.data['swap']['percent_used'] > 50

    def test_critical_swap(self, mock_context):
        """Returns 1 when swap usage exceeds critical threshold."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_CRITICAL_SWAP,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample'], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'critical'
        assert output.data['swap']['percent_used'] > 80

    def test_no_swap_configured(self, mock_context):
        """Reports info when no swap is configured."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_NO_SWAP,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample'], output, ctx)

        assert exit_code == 0
        assert output.data['swap_state'] == 'none'
        assert any(i['type'] == 'NO_SWAP' for i in output.data['issues'])

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds can be specified."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_HEALTHY,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample', '--warn', '1', '--crit', '5'], output, ctx)

        # Even low swap usage should trigger warning with low threshold
        assert exit_code == 1

    def test_invalid_threshold_returns_error(self, mock_context):
        """Returns 2 for invalid threshold values."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_HEALTHY,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample', '--warn', '80', '--crit', '50'], output, ctx)

        assert exit_code == 2

    def test_swap_state_unused(self, mock_context):
        """Detects unused swap state."""
        from scripts.baremetal import swap_pressure

        # Create meminfo with swap available but not used
        meminfo_unused = """MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   10240000 kB
Buffers:          512000 kB
Cached:          2048000 kB
SwapTotal:       8192000 kB
SwapFree:        8192000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo_unused,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample'], output, ctx)

        assert exit_code == 0
        assert output.data['swap_state'] == 'unused'

    def test_pressure_levels(self, mock_context):
        """Memory pressure levels are detected."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_HIGH_SWAP,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample'], output, ctx)

        assert output.data['pressure'] in ['low', 'moderate', 'high']

    def test_verbose_output(self, mock_context):
        """--verbose flag works."""
        from scripts.baremetal import swap_pressure

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': MEMINFO_HEALTHY,
            }
        )
        output = Output()

        exit_code = swap_pressure.run(['--no-sample', '--verbose'], output, ctx)

        assert exit_code == 0
        assert 'swap' in output.data
        assert 'memory' in output.data
