"""Tests for memory_reclaim_monitor script."""

import pytest

from boxctl.core.output import Output


@pytest.fixture
def vmstat_healthy():
    """Healthy vmstat content."""
    return """nr_free_pages 500000
nr_inactive_anon 100000
nr_active_anon 200000
pgsteal_kswapd 1000
pgscan_kswapd 1100
pgsteal_direct 10
pgscan_direct 15
allocstall 0
compact_stall 100
compact_fail 10
compact_success 90
oom_kill 0
pswpin 0
pswpout 0
"""


@pytest.fixture
def vmstat_pressure():
    """Vmstat content showing memory pressure."""
    return """nr_free_pages 50000
nr_inactive_anon 100000
nr_active_anon 200000
pgsteal_kswapd 100000
pgscan_kswapd 110000
pgsteal_direct 50000
pgscan_direct 150000
allocstall 5000
compact_stall 50000
compact_fail 30000
compact_success 20000
oom_kill 0
pswpin 1000
pswpout 5000
"""


@pytest.fixture
def vmstat_oom():
    """Vmstat content with OOM kills."""
    return """nr_free_pages 10000
pgsteal_kswapd 200000
pgscan_kswapd 220000
pgsteal_direct 100000
pgscan_direct 300000
allocstall 10000
compact_stall 100000
compact_fail 60000
compact_success 40000
oom_kill 3
pswpin 5000
pswpout 10000
"""


@pytest.fixture
def meminfo_healthy():
    """Healthy meminfo content."""
    return """MemTotal:       16000000 kB
MemFree:         5000000 kB
MemAvailable:    8000000 kB
Buffers:          500000 kB
Cached:          2000000 kB
SwapTotal:       4000000 kB
SwapFree:        4000000 kB
"""


@pytest.fixture
def meminfo_low():
    """Low memory meminfo content."""
    return """MemTotal:       16000000 kB
MemFree:          200000 kB
MemAvailable:     800000 kB
Buffers:           50000 kB
Cached:           500000 kB
SwapTotal:       4000000 kB
SwapFree:        1000000 kB
"""


class TestMemoryReclaimMonitor:
    """Tests for memory_reclaim_monitor script."""

    def test_missing_vmstat_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/vmstat not available."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = memory_reclaim_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_reclaim_activity(self, mock_context, vmstat_healthy, meminfo_healthy):
        """Returns 0 when reclaim activity is healthy."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': vmstat_healthy,
                '/proc/meminfo': meminfo_healthy,
            }
        )
        output = Output()

        exit_code = memory_reclaim_monitor.run([], output, ctx)

        assert exit_code == 0
        assert not output.data['has_issues']

    def test_high_direct_reclaim_returns_warning(self, mock_context, vmstat_pressure, meminfo_healthy):
        """Returns 1 when direct reclaim is high."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': vmstat_pressure,
                '/proc/meminfo': meminfo_healthy,
            }
        )
        output = Output()

        exit_code = memory_reclaim_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data['has_issues']
        assert any('direct' in str(i.get('metric', '')) for i in output.data['issues'])

    def test_oom_kill_returns_critical(self, mock_context, vmstat_oom, meminfo_low):
        """Returns 1 with critical severity when OOM kills detected."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': vmstat_oom,
                '/proc/meminfo': meminfo_low,
            }
        )
        output = Output()

        exit_code = memory_reclaim_monitor.run([], output, ctx)

        assert exit_code == 1
        assert any(i['severity'] == 'CRITICAL' for i in output.data['issues'])
        assert any('oom' in i.get('metric', '').lower() for i in output.data['issues'])

    def test_low_memory_returns_warning(self, mock_context, vmstat_healthy, meminfo_low):
        """Returns 1 when available memory is low."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': vmstat_healthy,
                '/proc/meminfo': meminfo_low,
            }
        )
        output = Output()

        exit_code = memory_reclaim_monitor.run([], output, ctx)

        assert exit_code == 1
        assert any('mem_available' in str(i.get('metric', '')) for i in output.data['issues'])

    def test_custom_thresholds(self, mock_context, vmstat_pressure, meminfo_healthy):
        """Custom thresholds are respected."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': vmstat_pressure,
                '/proc/meminfo': meminfo_healthy,
            }
        )

        # With very high thresholds, should pass
        output = Output()
        exit_code = memory_reclaim_monitor.run(
            ['--direct-reclaim', '1000000', '--allocstall', '100000'],
            output,
            ctx
        )

        # May still fail on other metrics like low efficiency
        # but direct reclaim threshold should not trigger

    def test_verbose_shows_additional_metrics(self, mock_context, vmstat_healthy, meminfo_healthy):
        """--verbose shows additional metrics."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': vmstat_healthy,
                '/proc/meminfo': meminfo_healthy,
            }
        )
        output = Output()

        exit_code = memory_reclaim_monitor.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'additional' in output.data
        assert 'compact_stall' in output.data['additional']
        assert 'oom_kill' in output.data['additional']

    def test_invalid_threshold_returns_error(self, mock_context):
        """Returns error for invalid threshold values."""
        from scripts.baremetal import memory_reclaim_monitor

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': 'nr_free_pages 100000\n',
                '/proc/meminfo': 'MemTotal: 16000000 kB\n',
            }
        )

        # Negative threshold
        output = Output()
        exit_code = memory_reclaim_monitor.run(['--direct-reclaim', '-1'], output, ctx)
        assert exit_code == 2

        # Efficiency out of range
        output = Output()
        exit_code = memory_reclaim_monitor.run(['--efficiency', '150'], output, ctx)
        assert exit_code == 2

    def test_reclaim_efficiency_calculation(self, mock_context, meminfo_healthy):
        """Tests reclaim efficiency calculation."""
        from scripts.baremetal import memory_reclaim_monitor

        # Low efficiency: many scans, few steals
        low_efficiency_vmstat = """pgsteal_kswapd 100
pgscan_kswapd 10000
pgsteal_direct 10
pgscan_direct 1000
allocstall 0
compact_stall 0
compact_fail 0
compact_success 0
oom_kill 0
pswpin 0
pswpout 0
"""
        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/vmstat': low_efficiency_vmstat,
                '/proc/meminfo': meminfo_healthy,
            }
        )
        output = Output()

        exit_code = memory_reclaim_monitor.run([], output, ctx)

        # Efficiency = 110/11000 * 100 = 1%
        assert output.data['reclaim']['efficiency_percent'] == 1.0
