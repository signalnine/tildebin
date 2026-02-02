"""Tests for network_qdisc_monitor script."""

import pytest

from boxctl.core.output import Output


@pytest.fixture
def tc_healthy():
    """Healthy tc qdisc output."""
    return """qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64
 Sent 1234567890 bytes 1234567 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
"""


@pytest.fixture
def tc_drops():
    """tc qdisc output with packet drops."""
    return """qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64
 Sent 1000000 bytes 100000 pkt (dropped 5000, overlimits 1000 requeues 100)
 backlog 0b 0p requeues 100
"""


@pytest.fixture
def tc_critical_drops():
    """tc qdisc output with critical packet drops."""
    return """qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64
 Sent 1000000 bytes 100000 pkt (dropped 10000, overlimits 5000 requeues 500)
 backlog 500b 50p requeues 500
"""


@pytest.fixture
def tc_backlog():
    """tc qdisc output with high backlog."""
    return """qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64
 Sent 1000000 bytes 100000 pkt (dropped 100, overlimits 50 requeues 10)
 backlog 50000b 5000p requeues 10
"""


@pytest.fixture
def tc_multiple_qdiscs():
    """tc qdisc output with multiple qdiscs."""
    return """qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64
 Sent 1000000 bytes 100000 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
qdisc ingress ffff: parent ffff:fff1 ----------------
 Sent 500000 bytes 50000 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
"""


class TestNetworkQdiscMonitor:
    """Tests for network_qdisc_monitor script."""

    def test_missing_tc_returns_error(self, mock_context):
        """Returns exit code 2 when tc not available."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=[],  # No tc
            file_contents={
                '/sys/class/net': '',
            }
        )
        output = Output()

        exit_code = network_qdisc_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('tc' in e.lower() for e in output.errors)

    def test_healthy_qdisc_returns_ok(self, mock_context, tc_healthy):
        """Returns 0 when qdiscs are healthy."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_healthy,
            }
        )
        output = Output()

        exit_code = network_qdisc_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['critical_count'] == 0
        assert output.data['summary']['warning_count'] == 0

    def test_drops_return_warning(self, mock_context, tc_drops):
        """Returns 1 when packet drops exceed warning threshold."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_drops,
            }
        )
        output = Output()

        exit_code = network_qdisc_monitor.run([], output, ctx)

        assert exit_code == 1
        # 5000 dropped out of 105000 total = ~4.76%
        assert output.data['summary']['warning_count'] >= 1

    def test_critical_drops(self, mock_context, tc_critical_drops):
        """Returns 1 with critical issues for high drop rate."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_critical_drops,
            }
        )
        output = Output()

        exit_code = network_qdisc_monitor.run([], output, ctx)

        assert exit_code == 1
        # 10000 dropped out of 110000 total = ~9.09% (> 5% critical)
        assert output.data['summary']['critical_count'] >= 1

    def test_high_backlog_returns_warning(self, mock_context, tc_backlog):
        """Returns warning when backlog is high."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_backlog,
            }
        )
        output = Output()

        exit_code = network_qdisc_monitor.run([], output, ctx)

        assert exit_code == 1
        # 5000 packets in backlog > 1000 warning threshold

    def test_custom_drop_thresholds(self, mock_context, tc_drops):
        """Custom drop thresholds are respected."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_drops,
            }
        )

        # With default thresholds (warn=1%, crit=5%), ~4.76% should be warning
        output = Output()
        exit_code = network_qdisc_monitor.run([], output, ctx)
        assert exit_code == 1

        # With higher thresholds, should be OK
        output = Output()
        exit_code = network_qdisc_monitor.run(
            ['--drop-warn', '10', '--drop-crit', '20'],
            output,
            ctx
        )
        assert exit_code == 0

    def test_custom_backlog_thresholds(self, mock_context, tc_backlog):
        """Custom backlog thresholds are respected."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_backlog,
            }
        )

        # With higher thresholds, should be OK
        output = Output()
        exit_code = network_qdisc_monitor.run(
            ['--backlog-warn', '10000', '--backlog-crit', '50000'],
            output,
            ctx
        )

        assert exit_code == 0

    def test_specific_interface(self, mock_context, tc_healthy, tc_drops):
        """Can monitor specific interfaces."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
                '/sys/class/net/eth1': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_healthy,
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth1'): tc_drops,
            }
        )

        # Only check eth0 (healthy)
        output = Output()
        exit_code = network_qdisc_monitor.run(['-i', 'eth0'], output, ctx)
        assert exit_code == 0

        # Only check eth1 (has drops)
        output = Output()
        exit_code = network_qdisc_monitor.run(['-i', 'eth1'], output, ctx)
        assert exit_code == 1

    def test_no_qdiscs_returns_ok(self, mock_context):
        """Returns 0 when no qdiscs are found."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): '',
            }
        )
        output = Output()

        exit_code = network_qdisc_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_qdiscs'] == 0

    def test_min_packets_filter(self, mock_context):
        """Low traffic qdiscs are filtered by min-packets."""
        from scripts.baremetal import network_qdisc_monitor

        # Low traffic qdisc
        tc_low_traffic = """qdisc fq_codel 0: root refcnt 2
 Sent 1000 bytes 100 pkt (dropped 50, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
"""
        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_low_traffic,
            }
        )

        # With default min-packets=1000, should ignore this qdisc
        output = Output()
        exit_code = network_qdisc_monitor.run([], output, ctx)
        assert exit_code == 0  # Filtered out

        # With lower min-packets, should detect issues
        output = Output()
        exit_code = network_qdisc_monitor.run(['--min-packets', '50'], output, ctx)
        assert exit_code == 1  # 50% drop rate detected

    def test_verbose_shows_all_qdiscs(self, mock_context, tc_healthy):
        """--verbose shows all qdisc statistics."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_healthy,
            }
        )
        output = Output()

        exit_code = network_qdisc_monitor.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'qdiscs' in output.data
        assert len(output.data['qdiscs']) > 0

    def test_invalid_threshold_returns_error(self, mock_context):
        """Returns error for invalid threshold values."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
            }
        )

        # Negative threshold
        output = Output()
        exit_code = network_qdisc_monitor.run(['--drop-warn', '-1'], output, ctx)
        assert exit_code == 2

        # Threshold > 100%
        output = Output()
        exit_code = network_qdisc_monitor.run(['--drop-warn', '150'], output, ctx)
        assert exit_code == 2

        # Warn > crit
        output = Output()
        exit_code = network_qdisc_monitor.run(
            ['--drop-warn', '10', '--drop-crit', '5'],
            output,
            ctx
        )
        assert exit_code == 2

    def test_include_loopback(self, mock_context, tc_healthy):
        """--include-loopback includes lo interface."""
        from scripts.baremetal import network_qdisc_monitor

        ctx = mock_context(
            tools_available=['tc'],
            file_contents={
                '/sys/class/net': '',
                '/sys/class/net/eth0': '',
                '/sys/class/net/lo': '',
            },
            command_outputs={
                ('tc', '-s', 'qdisc', 'show', 'dev', 'eth0'): tc_healthy,
                ('tc', '-s', 'qdisc', 'show', 'dev', 'lo'): tc_healthy,
            }
        )

        # Without loopback
        output = Output()
        exit_code = network_qdisc_monitor.run([], output, ctx)
        count_without_lo = output.data['summary']['total_qdiscs']

        # With loopback
        output = Output()
        exit_code = network_qdisc_monitor.run(['--include-loopback'], output, ctx)
        count_with_lo = output.data['summary']['total_qdiscs']

        assert count_with_lo >= count_without_lo
