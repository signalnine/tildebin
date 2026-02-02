"""Tests for udp_sockets script."""

import pytest

from boxctl.core.output import Output


class TestUdpSockets:
    """Tests for UDP socket monitor."""

    def test_missing_proc_udp_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/net/udp not available."""
        from scripts.baremetal import udp_sockets

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = udp_sockets.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any('/proc/net/udp' in e for e in output.errors)

    def test_healthy_no_sockets(self, mock_context):
        """Returns 0 when no UDP sockets."""
        from scripts.baremetal import udp_sockets

        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        exit_code = udp_sockets.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_sockets'] == 0

    def test_healthy_few_sockets(self, mock_context):
        """Returns 0 with healthy socket count."""
        from scripts.baremetal import udp_sockets

        # Two sockets: DNS client on port 53, NTP on port 123
        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 12345 2 0000000000000000 0
   1: 00000000:007B 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12346 2 0000000000000000 0
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        exit_code = udp_sockets.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_sockets'] == 2
        assert output.data['status'] == 'ok'

    def test_high_socket_count_warning(self, mock_context):
        """Returns 1 when socket count exceeds threshold."""
        from scripts.baremetal import udp_sockets

        # Generate many socket lines
        lines = [
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"
        ]
        for i in range(100):
            port_hex = format(10000 + i, '04X')
            lines.append(
                f"   {i}: 00000000:{port_hex} 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 {12345 + i} 2 0000000000000000 0"
            )

        udp_content = "\n".join(lines)

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        # With threshold of 50, 100 sockets should trigger warning
        exit_code = udp_sockets.run(['--socket-warn', '50'], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'warning'
        assert any(i['type'] == 'SOCKET_COUNT_HIGH' for i in output.data['issues'])

    def test_high_rx_queue_warning(self, mock_context):
        """Returns 1 when RX queue exceeds threshold."""
        from scripts.baremetal import udp_sockets

        # Socket with large RX queue (2MB in hex = 0x200000)
        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00200000 00:00000000 00000000   101        0 12345 2 0000000000000000 0
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        exit_code = udp_sockets.run(['--rx-queue-warn', '1000000'], output, ctx)

        assert exit_code == 1
        assert any(i['type'] == 'RX_QUEUE_HIGH' for i in output.data['issues'])

    def test_filter_by_port(self, mock_context):
        """Can filter sockets by port."""
        from scripts.baremetal import udp_sockets

        # Two sockets: one on port 53, one on port 123
        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 12345 2 0000000000000000 0
   1: 00000000:007B 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12346 2 0000000000000000 0
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        # Filter to port 53 only
        exit_code = udp_sockets.run(['--port', '53'], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_sockets'] == 1

    def test_invalid_regex_returns_error(self, mock_context):
        """Returns 2 for invalid process regex."""
        from scripts.baremetal import udp_sockets

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': "  sl  local_address rem_address\n",
            }
        )
        output = Output()

        # Invalid regex pattern
        exit_code = udp_sockets.run(['--process', '[invalid('], output, ctx)

        assert exit_code == 2
        assert any('pattern' in e.lower() for e in output.errors)

    def test_verbose_includes_socket_details(self, mock_context):
        """--verbose includes individual socket details."""
        from scripts.baremetal import udp_sockets

        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00000100 00:00000000 00000000   101        0 12345 2 0000000000000000 5
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        exit_code = udp_sockets.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert 'sockets' in output.data
        assert len(output.data['sockets']) == 1
        assert output.data['sockets'][0]['local_port'] == 53
        assert output.data['sockets'][0]['rx_queue'] == 256  # 0x100

    def test_includes_ipv6_sockets(self, mock_context):
        """Includes IPv6 sockets from /proc/net/udp6."""
        from scripts.baremetal import udp_sockets

        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 12345 2 0000000000000000 0
"""

        udp6_content = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 12346 2 0000000000000000 0
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
                '/proc/net/udp6': udp6_content,
            }
        )
        output = Output()

        exit_code = udp_sockets.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_sockets'] == 2

    def test_per_socket_rx_queue_warning(self, mock_context):
        """Warns when individual socket has high RX queue."""
        from scripts.baremetal import udp_sockets

        # Socket with 100KB+ in RX queue (0x19000 = 102400)
        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00019000 00:00000000 00000000   101        0 12345 2 0000000000000000 0
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        exit_code = udp_sockets.run([], output, ctx)

        assert exit_code == 1
        assert any(i['type'] == 'SOCKET_RX_QUEUE_HIGH' for i in output.data['issues'])

    def test_port_statistics(self, mock_context):
        """Generates port-based statistics."""
        from scripts.baremetal import udp_sockets

        # Multiple sockets on same port
        udp_content = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00000100 00:00000000 00000000   101        0 12345 2 0000000000000000 0
   1: 0200007F:0035 00000000:0000 07 00000000:00000200 00:00000000 00000000   101        0 12346 2 0000000000000000 0
"""

        ctx = mock_context(
            file_contents={
                '/proc/net/udp': udp_content,
            }
        )
        output = Output()

        exit_code = udp_sockets.run([], output, ctx)

        assert exit_code == 0
        assert '53' in output.data['by_port']
        assert output.data['by_port']['53']['count'] == 2
        assert output.data['by_port']['53']['total_rx_queue'] == 0x100 + 0x200
