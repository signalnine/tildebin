"""Tests for writeback script."""

import pytest

from boxctl.core.output import Output


class TestWriteback:
    """Tests for writeback monitor."""

    def test_missing_meminfo_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/meminfo not available."""
        from scripts.baremetal import writeback

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('/proc/meminfo' in e for e in output.errors)

    def test_healthy_writeback(self, mock_context):
        """Returns 0 when writeback is healthy."""
        from scripts.baremetal import writeback

        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:             10240 kB
Writeback:          1024 kB
"""

        vmstat = """nr_dirty 2560
nr_writeback 256
nr_writeback_temp 0
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': vmstat,
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert len(output.data['issues']) == 0

    def test_high_dirty_pages_warning(self, mock_context):
        """Returns 1 when dirty pages exceed warning threshold."""
        from scripts.baremetal import writeback

        # 6% dirty (1006632 kB of 16777216 kB)
        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:           1006632 kB
Writeback:          1024 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'warning'
        assert any('elevated' in i.lower() or 'dirty' in i.lower() for i in output.data['issues'])

    def test_critical_dirty_pages(self, mock_context):
        """Returns 1 when dirty pages exceed critical threshold."""
        from scripts.baremetal import writeback

        # 12% dirty (2013265 kB of 16777216 kB)
        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:           2013265 kB
Writeback:          1024 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'critical'
        assert any('critical' in i.lower() for i in output.data['issues'])

    def test_approaching_dirty_ratio_limit(self, mock_context):
        """Warns when approaching kernel dirty_ratio limit."""
        from scripts.baremetal import writeback

        # dirty_ratio is 20%, we're at 18% (90% of limit)
        # 18% of 16GB = 3019898 kB
        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:           3019898 kB
Writeback:          1024 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 1
        assert any('dirty_ratio' in i.lower() or 'throttle' in i.lower() for i in output.data['issues'])

    def test_high_writeback_volume(self, mock_context):
        """Warns when writeback volume is high."""
        from scripts.baremetal import writeback

        # 6% in writeback (1006632 kB)
        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:             10240 kB
Writeback:       1006632 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 1
        assert any('writeback' in i.lower() and 'flight' in i.lower() for i in output.data['issues'])

    def test_custom_thresholds(self, mock_context):
        """Custom warning/critical thresholds work."""
        from scripts.baremetal import writeback

        # 3% dirty
        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:            503316 kB
Writeback:          1024 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )

        # With default 5% warn, 3% should be fine
        output1 = Output()
        exit_code1 = writeback.run([], output1, ctx)
        assert exit_code1 == 0

        # With 2% warn threshold, 3% should trigger warning
        output2 = Output()
        exit_code2 = writeback.run(['--warn-pct', '2', '--crit-pct', '8'], output2, ctx)
        assert exit_code2 == 1
        assert output2.data['status'] == 'warning'

    def test_invalid_thresholds_returns_error(self, mock_context):
        """Returns 2 for invalid threshold arguments."""
        from scripts.baremetal import writeback

        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:             10240 kB
Writeback:          1024 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )
        output = Output()

        # warn > crit is invalid
        exit_code = writeback.run(['--warn-pct', '15', '--crit-pct', '10'], output, ctx)

        assert exit_code == 2
        assert any('warn' in e.lower() for e in output.errors)

    def test_verbose_includes_bdi_stats(self, mock_context):
        """--verbose includes BDI device stats."""
        from scripts.baremetal import writeback

        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:             10240 kB
Writeback:          1024 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
                '/sys/class/bdi': '',  # directory marker
                '/sys/class/bdi/8:0': '',  # device directory
                '/sys/class/bdi/8:0/read_ahead_kb': '128',
                '/sys/class/bdi/8:0/min_ratio': '0',
                '/sys/class/bdi/8:0/max_ratio': '100',
            }
        )
        output = Output()

        exit_code = writeback.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'bdi_devices' in output.data
        assert len(output.data['bdi_devices']) >= 1

    def test_metrics_include_settings(self, mock_context):
        """Output includes writeback settings."""
        from scripts.baremetal import writeback

        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
Dirty:             10240 kB
Writeback:          1024 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': '',
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 0
        assert 'settings' in output.data
        assert output.data['settings']['dirty_ratio'] == 20
        assert output.data['settings']['dirty_background_ratio'] == 10

    def test_uses_vmstat_counters(self, mock_context):
        """Uses vmstat counters when available."""
        from scripts.baremetal import writeback

        meminfo = """MemTotal:       16777216 kB
MemFree:         8000000 kB
"""

        # vmstat has nr_dirty in pages (4KB each)
        # 2560 pages * 4096 = 10485760 bytes = 10MB
        vmstat = """nr_dirty 2560
nr_writeback 256
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmstat': vmstat,
                '/proc/sys/vm/dirty_ratio': '20',
                '/proc/sys/vm/dirty_background_ratio': '10',
                '/proc/sys/vm/dirty_bytes': '0',
                '/proc/sys/vm/dirty_background_bytes': '0',
                '/proc/sys/vm/dirty_expire_centisecs': '3000',
                '/proc/sys/vm/dirty_writeback_centisecs': '500',
            }
        )
        output = Output()

        exit_code = writeback.run([], output, ctx)

        assert exit_code == 0
        # 2560 pages * 4096 bytes = 10485760 bytes
        assert output.data['metrics']['dirty_bytes'] == 2560 * 4096
