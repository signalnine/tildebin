"""Tests for page_cache script."""

import pytest

from boxctl.core.output import Output


class TestPageCache:
    """Tests for page_cache script."""

    def test_meminfo_not_available_returns_error(self, mock_context):
        """Returns 2 when /proc/meminfo not available."""
        from scripts.baremetal import page_cache

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = page_cache.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_page_cache(self, mock_context):
        """Returns 0 when page cache is healthy."""
        from scripts.baremetal import page_cache

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
Buffers:          500000 kB
Cached:          3000000 kB
Dirty:             10000 kB
Writeback:             0 kB
Active:          6000000 kB
Inactive:        4000000 kB
Active(file):    2000000 kB
Inactive(file):  1500000 kB
Slab:             500000 kB
SReclaimable:     400000 kB
SUnreclaim:       100000 kB
""",
                '/proc/vmstat': 'pgsteal_kswapd 1000\npgscan_kswapd 2000\n',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = page_cache.run([], output, ctx)

        assert exit_code == 0
        assert 'page_cache' in output.data
        assert 'dirty_pages' in output.data
        assert len(output.data['issues']) == 0

    def test_high_dirty_pages_warning(self, mock_context):
        """Returns 1 when dirty pages exceed warning threshold."""
        from scripts.baremetal import page_cache

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
Buffers:          500000 kB
Cached:          3000000 kB
Dirty:          2000000 kB
Writeback:        100000 kB
Active:          6000000 kB
Inactive:        4000000 kB
Active(file):    2000000 kB
Inactive(file):  1500000 kB
""",
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
            }
        )
        output = Output()

        exit_code = page_cache.run(['--dirty-warn', '10'], output, ctx)

        assert exit_code == 1
        assert any(i['type'] == 'high_dirty_pages' for i in output.data['issues'])

    def test_low_available_memory_critical(self, mock_context):
        """Returns 1 when available memory is critically low."""
        from scripts.baremetal import page_cache

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:          200000 kB
MemAvailable:     500000 kB
Buffers:          100000 kB
Cached:           500000 kB
Dirty:             10000 kB
Writeback:             0 kB
Active:         14000000 kB
Inactive:        1000000 kB
Active(file):     200000 kB
Inactive(file):   100000 kB
""",
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
            }
        )
        output = Output()

        exit_code = page_cache.run([], output, ctx)

        assert exit_code == 1
        assert any(i['type'] == 'low_available_memory' for i in output.data['issues'])

    def test_verbose_includes_limits(self, mock_context):
        """Verbose mode includes dirty limits."""
        from scripts.baremetal import page_cache

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': """MemTotal:       16000000 kB
MemFree:         4000000 kB
MemAvailable:    8000000 kB
Buffers:          500000 kB
Cached:          3000000 kB
Dirty:             10000 kB
Writeback:             0 kB
Active:          6000000 kB
Inactive:        4000000 kB
Active(file):    2000000 kB
Inactive(file):  1500000 kB
""",
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
            }
        )
        output = Output()

        exit_code = page_cache.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'limits' in output.data
        assert output.data['limits']['dirty_ratio'] == 20

    def test_invalid_thresholds_returns_error(self, mock_context):
        """Returns 2 for invalid threshold configuration."""
        from scripts.baremetal import page_cache

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': 'MemTotal: 16000000 kB\n',
            }
        )
        output = Output()

        # dirty-warn >= dirty-crit is invalid
        exit_code = page_cache.run(['--dirty-warn', '25', '--dirty-crit', '20'], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
