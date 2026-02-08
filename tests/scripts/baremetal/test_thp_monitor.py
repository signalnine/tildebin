"""Tests for thp_monitor script."""

import json
import pytest

from boxctl.core.output import Output


VMSTAT_HEALTHY = """compact_stall 100
compact_fail 10
compact_success 90
thp_fault_alloc 50000
thp_fault_fallback 1000
thp_collapse_alloc 10000
thp_collapse_alloc_failed 500
"""

VMSTAT_HIGH_STALLS = """compact_stall 50000
compact_fail 10000
compact_success 40000
thp_fault_alloc 10000
thp_fault_fallback 1000
thp_collapse_alloc 5000
thp_collapse_alloc_failed 200
"""

VMSTAT_HIGH_FALLBACK = """compact_stall 100
compact_fail 10
compact_success 90
thp_fault_alloc 5000
thp_fault_fallback 20000
thp_collapse_alloc 5000
thp_collapse_alloc_failed 200
"""


class TestThpMonitor:
    """Tests for thp_monitor script."""

    def test_no_thp_support(self, mock_context):
        """Returns exit code 2 when THP not available."""
        from scripts.baremetal.thp_monitor import run

        ctx = mock_context(file_contents={})
        output = Output()

        assert run([], output, ctx) == 2

    def test_thp_healthy(self, mock_context):
        """Returns 0 when THP is healthy with low stalls and fallbacks."""
        from scripts.baremetal.thp_monitor import run

        ctx = mock_context(file_contents={
            '/sys/kernel/mm/transparent_hugepage/enabled': 'always [madvise] never',
            '/sys/kernel/mm/transparent_hugepage/defrag': 'always defer defer+madvise [madvise] never',
            '/proc/vmstat': VMSTAT_HEALTHY,
            '/sys/kernel/mm/transparent_hugepage/khugepaged/pages_to_scan': '4096',
            '/sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs': '10000',
        })
        output = Output()

        assert run([], output, ctx) == 0

    def test_high_compaction_stalls(self, mock_context):
        """Returns 1 when compact_stall is high with THP always."""
        from scripts.baremetal.thp_monitor import run

        ctx = mock_context(file_contents={
            '/sys/kernel/mm/transparent_hugepage/enabled': '[always] madvise never',
            '/sys/kernel/mm/transparent_hugepage/defrag': '[madvise] never',
            '/proc/vmstat': VMSTAT_HIGH_STALLS,
        })
        output = Output()

        assert run([], output, ctx) == 1

    def test_high_fallback_ratio(self, mock_context):
        """Returns 1 when THP fault fallback ratio exceeds 50%."""
        from scripts.baremetal.thp_monitor import run

        ctx = mock_context(file_contents={
            '/sys/kernel/mm/transparent_hugepage/enabled': '[always] madvise never',
            '/sys/kernel/mm/transparent_hugepage/defrag': '[madvise] never',
            '/proc/vmstat': VMSTAT_HIGH_FALLBACK,
        })
        output = Output()

        assert run([], output, ctx) == 1

    def test_thp_disabled(self, mock_context):
        """Returns 0 with INFO when THP is disabled."""
        from scripts.baremetal.thp_monitor import run

        ctx = mock_context(file_contents={
            '/sys/kernel/mm/transparent_hugepage/enabled': 'always madvise [never]',
            '/sys/kernel/mm/transparent_hugepage/defrag': 'always madvise [never]',
            '/proc/vmstat': VMSTAT_HEALTHY,
        })
        output = Output()

        assert run([], output, ctx) == 0

    def test_json_output(self, mock_context, capsys):
        """JSON output has expected structure."""
        from scripts.baremetal.thp_monitor import run

        ctx = mock_context(file_contents={
            '/sys/kernel/mm/transparent_hugepage/enabled': 'always [madvise] never',
            '/sys/kernel/mm/transparent_hugepage/defrag': '[madvise] never',
            '/proc/vmstat': VMSTAT_HEALTHY,
        })
        output = Output()

        run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "thp_settings" in data
        assert "vmstat" in data
        assert "issues" in data
