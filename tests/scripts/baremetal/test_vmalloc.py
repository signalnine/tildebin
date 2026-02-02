"""Tests for vmalloc script."""

import pytest

from boxctl.core.output import Output


class TestVmalloc:
    """Tests for vmalloc monitor."""

    def test_missing_meminfo_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/meminfo not available."""
        from scripts.baremetal import vmalloc

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = vmalloc.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('/proc/meminfo' in e for e in output.errors)

    def test_healthy_vmalloc(self, mock_context):
        """Returns 0 when vmalloc usage is healthy."""
        from scripts.baremetal import vmalloc

        meminfo = """MemTotal:       16384000 kB
MemFree:         8000000 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       500000 kB
VmallocChunk:   34359000000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )
        output = Output()

        exit_code = vmalloc.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'healthy'
        assert output.data['used_kb'] == 500000

    def test_high_usage_warning(self, mock_context):
        """Returns 1 when vmalloc usage exceeds warning threshold."""
        from scripts.baremetal import vmalloc

        # 85% used (85000 of 100000 kB)
        meminfo = """MemTotal:       16384000 kB
MemFree:         8000000 kB
VmallocTotal:      100000 kB
VmallocUsed:        85000 kB
VmallocChunk:       15000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )
        output = Output()

        exit_code = vmalloc.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'warning'
        assert any('85' in i['message'] for i in output.data['issues'])

    def test_critical_usage(self, mock_context):
        """Returns 1 when vmalloc usage exceeds critical threshold."""
        from scripts.baremetal import vmalloc

        # 96% used (96000 of 100000 kB)
        meminfo = """MemTotal:       16384000 kB
MemFree:         8000000 kB
VmallocTotal:      100000 kB
VmallocUsed:        96000 kB
VmallocChunk:        4000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )
        output = Output()

        exit_code = vmalloc.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'critical'
        assert any(i['severity'] == 'critical' for i in output.data['issues'])

    def test_small_contiguous_block_warning(self, mock_context):
        """Warns when largest contiguous block is too small."""
        from scripts.baremetal import vmalloc

        # Large total, but fragmented (chunk only 16MB)
        meminfo = """MemTotal:       16384000 kB
MemFree:         8000000 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       500000 kB
VmallocChunk:       16384 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )
        output = Output()

        exit_code = vmalloc.run([], output, ctx)

        assert exit_code == 1
        assert any('contiguous' in i['message'].lower() for i in output.data['issues'])

    def test_custom_thresholds(self, mock_context):
        """Custom warning/critical thresholds work."""
        from scripts.baremetal import vmalloc

        # 60% used (60000 of 100000 kB)
        meminfo = """MemTotal:       16384000 kB
MemFree:         8000000 kB
VmallocTotal:      100000 kB
VmallocUsed:        60000 kB
VmallocChunk:       40000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )

        # With default 80% warn, 60% should be fine
        output1 = Output()
        exit_code1 = vmalloc.run([], output1, ctx)
        assert exit_code1 == 0

        # With 50% warn threshold, 60% should trigger warning
        output2 = Output()
        exit_code2 = vmalloc.run(['--warn-pct', '50', '--crit-pct', '90'], output2, ctx)
        assert exit_code2 == 1
        assert output2.data['status'] == 'warning'

    def test_invalid_thresholds_returns_error(self, mock_context):
        """Returns 2 for invalid threshold arguments."""
        from scripts.baremetal import vmalloc

        meminfo = """VmallocTotal:      100000 kB
VmallocUsed:        50000 kB
VmallocChunk:       50000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )
        output = Output()

        # warn >= crit is invalid
        exit_code = vmalloc.run(['--warn-pct', '90', '--crit-pct', '80'], output, ctx)

        assert exit_code == 2
        assert any('warn' in e.lower() for e in output.errors)

    def test_verbose_includes_top_consumers(self, mock_context):
        """--verbose includes top consumers when vmallocinfo available."""
        from scripts.baremetal import vmalloc

        meminfo = """VmallocTotal:      100000 kB
VmallocUsed:        50000 kB
VmallocChunk:       50000 kB
"""

        vmallocinfo = """0xffffc90000000000-0xffffc90000100000  1048576 module_alloc+0x5f/0x90
0xffffc90000100000-0xffffc90000200000  1048576 module_alloc+0x5f/0x90
0xffffc90000200000-0xffffc90000210000    65536 bpf_jit_alloc_exec+0x10/0x20
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                '/proc/vmallocinfo': vmallocinfo,
            }
        )
        output = Output()

        exit_code = vmalloc.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert output.data['has_details'] is True
        assert 'top_consumers' in output.data
        assert len(output.data['top_consumers']) > 0
        # module_alloc should have 2 allocations
        module_alloc = next(
            (c for c in output.data['top_consumers'] if 'module_alloc' in c['name']),
            None
        )
        assert module_alloc is not None
        assert module_alloc['count'] == 2

    def test_no_vmallocinfo_still_works(self, mock_context):
        """Works without /proc/vmallocinfo (just no detailed breakdown)."""
        from scripts.baremetal import vmalloc

        meminfo = """VmallocTotal:      100000 kB
VmallocUsed:        50000 kB
VmallocChunk:       50000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
                # No vmallocinfo
            }
        )
        output = Output()

        exit_code = vmalloc.run([], output, ctx)

        assert exit_code == 0
        assert output.data['has_details'] is False

    def test_zero_vmalloc_total_returns_error(self, mock_context):
        """Returns 2 when VmallocTotal is missing or zero."""
        from scripts.baremetal import vmalloc

        meminfo = """MemTotal:       16384000 kB
MemFree:         8000000 kB
VmallocUsed:        50000 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )
        output = Output()

        exit_code = vmalloc.run([], output, ctx)

        assert exit_code == 2
        assert any('VmallocTotal' in e for e in output.errors)

    def test_custom_min_chunk(self, mock_context):
        """Custom minimum chunk size threshold."""
        from scripts.baremetal import vmalloc

        # Chunk is 64MB
        meminfo = """VmallocTotal:   34359738367 kB
VmallocUsed:       500000 kB
VmallocChunk:       65536 kB
"""

        ctx = mock_context(
            file_contents={
                '/proc/meminfo': meminfo,
            }
        )

        # With default 32MB min, 64MB chunk should be fine
        output1 = Output()
        exit_code1 = vmalloc.run([], output1, ctx)
        assert exit_code1 == 0

        # With 100MB min, 64MB chunk should warn
        output2 = Output()
        exit_code2 = vmalloc.run(['--min-chunk', '100'], output2, ctx)
        assert exit_code2 == 1
        assert any('contiguous' in i['message'].lower() for i in output2.data['issues'])
