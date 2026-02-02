"""Tests for network_peer_latency script."""

import pytest

from boxctl.core.output import Output


@pytest.fixture
def ping_success():
    """Successful ping output."""
    return """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.523 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.456 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=0.512 ms
64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=0.489 ms
64 bytes from 192.168.1.1: icmp_seq=5 ttl=64 time=0.501 ms

--- 192.168.1.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4005ms
rtt min/avg/max/mdev = 0.456/0.496/0.523/0.023 ms
"""


@pytest.fixture
def ping_high_latency():
    """Ping output with high latency."""
    return """PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=75.523 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=82.456 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=79.512 ms
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=81.489 ms
64 bytes from 10.0.0.1: icmp_seq=5 ttl=64 time=78.501 ms

--- 10.0.0.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4005ms
rtt min/avg/max/mdev = 75.523/79.496/82.456/2.423 ms
"""


@pytest.fixture
def ping_packet_loss():
    """Ping output with packet loss."""
    return """PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=1.523 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=1.512 ms
64 bytes from 10.0.0.2: icmp_seq=5 ttl=64 time=1.501 ms

--- 10.0.0.2 ping statistics ---
5 packets transmitted, 3 received, 40% packet loss, time 4005ms
rtt min/avg/max/mdev = 1.501/1.512/1.523/0.009 ms
"""


@pytest.fixture
def ping_unreachable():
    """Ping output for unreachable host."""
    return """PING 10.0.0.99 (10.0.0.99) 56(84) bytes of data.

--- 10.0.0.99 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4005ms
"""


@pytest.fixture
def ip_route_default():
    """Default route output."""
    return """default via 192.168.1.1 dev eth0 proto static metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
"""


class TestNetworkPeerLatency:
    """Tests for network_peer_latency script."""

    def test_missing_ping_returns_error(self, mock_context):
        """Returns exit code 2 when ping not available."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=[],  # No ping
            command_outputs={
                ('ip', 'route', 'show', 'default'): 'default via 192.168.1.1 dev eth0\n',
            }
        )
        output = Output()

        exit_code = network_peer_latency.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_gateway_no_targets_returns_error(self, mock_context):
        """Returns error when no gateway found and no targets specified."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ip', 'route', 'show', 'default'): '',  # No default route
            }
        )
        output = Output()

        exit_code = network_peer_latency.run([], output, ctx)

        assert exit_code == 2

    def test_successful_ping_returns_healthy(self, mock_context, ping_success, ip_route_default):
        """Returns 0 when ping is successful with low latency."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ip', 'route', 'show', 'default'): ip_route_default,
                ('ping', '-c', '5', '-W', '2', '192.168.1.1'): ping_success,
            }
        )
        output = Output()

        exit_code = network_peer_latency.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['ok'] == 1
        assert output.data['results'][0]['reachable'] is True
        assert output.data['results'][0]['avg_ms'] < 1.0

    def test_high_latency_returns_warning(self, mock_context, ping_high_latency):
        """Returns 1 when latency exceeds warning threshold."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ping', '-c', '5', '-W', '2', '10.0.0.1'): ping_high_latency,
            }
        )
        output = Output()

        exit_code = network_peer_latency.run(['--targets', '10.0.0.1'], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['warning'] >= 1
        assert output.data['results'][0]['status'] == 'warning'

    def test_critical_latency(self, mock_context):
        """Returns 1 with critical status when latency exceeds critical threshold."""
        from scripts.baremetal import network_peer_latency

        # Very high latency ping output
        ping_critical = """PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=150.523 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=162.456 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=155.512 ms

--- 10.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 150.523/156.164/162.456/4.923 ms
"""
        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ping', '-c', '5', '-W', '2', '10.0.0.1'): ping_critical,
            }
        )
        output = Output()

        exit_code = network_peer_latency.run(['--targets', '10.0.0.1'], output, ctx)

        assert exit_code == 1
        assert output.data['results'][0]['status'] == 'critical'

    def test_packet_loss_returns_warning(self, mock_context, ping_packet_loss):
        """Returns warning when packet loss exceeds threshold."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ping', '-c', '5', '-W', '2', '10.0.0.2'): ping_packet_loss,
            }
        )
        output = Output()

        exit_code = network_peer_latency.run(['--targets', '10.0.0.2'], output, ctx)

        assert exit_code == 1
        # Should have packet loss warning
        assert 'packet loss' in str(output.data['results'][0]['issues'])

    def test_unreachable_host_returns_critical(self, mock_context, ping_unreachable):
        """Returns critical when host is unreachable."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ping', '-c', '5', '-W', '2', '10.0.0.99'): ping_unreachable,
            }
        )
        output = Output()

        exit_code = network_peer_latency.run(['--targets', '10.0.0.99'], output, ctx)

        assert exit_code == 1
        assert output.data['results'][0]['status'] == 'critical'
        assert output.data['results'][0]['reachable'] is False

    def test_multiple_targets(self, mock_context, ping_success, ping_high_latency):
        """Handles multiple targets correctly."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ping', '-c', '5', '-W', '2', '192.168.1.1'): ping_success,
                ('ping', '-c', '5', '-W', '2', '10.0.0.1'): ping_high_latency,
            }
        )
        output = Output()

        exit_code = network_peer_latency.run(
            ['--targets', '192.168.1.1,10.0.0.1'],
            output,
            ctx
        )

        assert exit_code == 1  # One has warning
        assert len(output.data['results']) == 2
        assert output.data['summary']['total_targets'] == 2
        assert output.data['summary']['ok'] == 1
        assert output.data['summary']['warning'] == 1

    def test_custom_thresholds(self, mock_context, ping_high_latency):
        """Custom thresholds are respected."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ping', '-c', '5', '-W', '2', '10.0.0.1'): ping_high_latency,
            }
        )

        # With default thresholds (warn=50ms), ~80ms avg should be warning
        output = Output()
        exit_code = network_peer_latency.run(['--targets', '10.0.0.1'], output, ctx)
        assert output.data['results'][0]['status'] == 'warning'

        # With higher threshold, should be OK
        output = Output()
        exit_code = network_peer_latency.run(
            ['--targets', '10.0.0.1', '--warn-ms', '100'],
            output,
            ctx
        )
        assert output.data['results'][0]['status'] == 'ok'

    def test_custom_count(self, mock_context):
        """Custom probe count is used."""
        from scripts.baremetal import network_peer_latency

        ping_3_count = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.523 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.456 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=0.512 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2005ms
rtt min/avg/max/mdev = 0.456/0.497/0.523/0.028 ms
"""
        ctx = mock_context(
            tools_available=['ping'],
            command_outputs={
                ('ping', '-c', '3', '-W', '2', '192.168.1.1'): ping_3_count,
            }
        )
        output = Output()

        exit_code = network_peer_latency.run(
            ['--targets', '192.168.1.1', '--count', '3'],
            output,
            ctx
        )

        assert exit_code == 0
        assert output.data['results'][0]['packets_sent'] == 3

    def test_tcp_mode_skips_ping_check(self, mock_context):
        """TCP mode doesn't require ping command."""
        from scripts.baremetal import network_peer_latency

        ctx = mock_context(
            tools_available=[],  # No ping
            command_outputs={}
        )
        output = Output()

        # TCP mode with unreachable host (socket will fail)
        exit_code = network_peer_latency.run(
            ['--tcp', '--targets', '192.0.2.1', '--timeout', '1', '--count', '1'],
            output,
            ctx
        )

        # Should complete (with unreachable target) rather than error on missing ping
        assert exit_code == 1  # Target unreachable
        assert output.data['results'][0]['method'] == 'tcp'
