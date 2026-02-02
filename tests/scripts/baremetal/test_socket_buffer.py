"""Tests for socket_buffer script."""

import pytest

from boxctl.core.output import Output


SOCKSTAT_HEALTHY = """sockets: used 1234
TCP: inuse 100 orphan 5 tw 50 alloc 150 mem 100
UDP: inuse 20 mem 10
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0
"""

SOCKSTAT_HIGH_TCP = """sockets: used 5000
TCP: inuse 500 orphan 50 tw 500 alloc 600 mem 80000
UDP: inuse 100 mem 50
"""

SOCKSTAT_HIGH_ORPHAN = """sockets: used 2000
TCP: inuse 200 orphan 1500 tw 100 alloc 300 mem 500
UDP: inuse 50 mem 25
"""

SOCKSTAT_HIGH_TIMEWAIT = """sockets: used 20000
TCP: inuse 1000 orphan 10 tw 15000 alloc 1100 mem 1000
UDP: inuse 100 mem 50
"""

SOCKSTAT6_EMPTY = """TCP6: inuse 0
UDP6: inuse 0
"""

TCP_MEM_NORMAL = "3096 4128 6192"
TCP_MEM_SMALL = "1000 2000 3000"
UDP_MEM_NORMAL = "6192 8256 12384"
RMEM_DEFAULT = "212992"
RMEM_MAX = "16777216"
WMEM_DEFAULT = "212992"
WMEM_MAX = "16777216"


class TestSocketBuffer:
    """Tests for socket_buffer script."""

    def test_no_sockstat_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/net/sockstat not available."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = socket_buffer.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("sockstat" in e.lower() for e in output.errors)

    def test_healthy_socket_buffers(self, mock_context):
        """Returns 0 when socket buffers are healthy."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(
            file_contents={
                '/proc/net/sockstat': SOCKSTAT_HEALTHY,
                '/proc/net/sockstat6': SOCKSTAT6_EMPTY,
                '/proc/sys/net/ipv4/tcp_mem': TCP_MEM_NORMAL,
                '/proc/sys/net/ipv4/udp_mem': UDP_MEM_NORMAL,
                '/proc/sys/net/core/rmem_default': RMEM_DEFAULT,
                '/proc/sys/net/core/rmem_max': RMEM_MAX,
                '/proc/sys/net/core/wmem_default': WMEM_DEFAULT,
                '/proc/sys/net/core/wmem_max': WMEM_MAX,
            }
        )
        output = Output()

        exit_code = socket_buffer.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert 'TCP' in output.data['protocols']

    def test_high_tcp_memory_pressure(self, mock_context):
        """Returns 1 when TCP memory is high."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(
            file_contents={
                '/proc/net/sockstat': SOCKSTAT_HIGH_TCP,
                '/proc/net/sockstat6': SOCKSTAT6_EMPTY,
                '/proc/sys/net/ipv4/tcp_mem': TCP_MEM_SMALL,
                '/proc/sys/net/ipv4/udp_mem': UDP_MEM_NORMAL,
            }
        )
        output = Output()

        exit_code = socket_buffer.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] in ['critical', 'warning']
        assert len(output.data['issues']) > 0 or len(output.data['warnings']) > 0

    def test_high_orphan_warning(self, mock_context):
        """Returns 1 when orphan socket count is high."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(
            file_contents={
                '/proc/net/sockstat': SOCKSTAT_HIGH_ORPHAN,
                '/proc/net/sockstat6': SOCKSTAT6_EMPTY,
                '/proc/sys/net/ipv4/tcp_mem': TCP_MEM_NORMAL,
                '/proc/sys/net/ipv4/udp_mem': UDP_MEM_NORMAL,
            }
        )
        output = Output()

        exit_code = socket_buffer.run([], output, ctx)

        assert exit_code == 1
        assert any('orphan' in w['message'].lower() for w in output.data['warnings'])

    def test_high_timewait_warning(self, mock_context):
        """Returns 1 when TIME_WAIT socket count is high."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(
            file_contents={
                '/proc/net/sockstat': SOCKSTAT_HIGH_TIMEWAIT,
                '/proc/net/sockstat6': SOCKSTAT6_EMPTY,
                '/proc/sys/net/ipv4/tcp_mem': TCP_MEM_NORMAL,
                '/proc/sys/net/ipv4/udp_mem': UDP_MEM_NORMAL,
            }
        )
        output = Output()

        exit_code = socket_buffer.run([], output, ctx)

        assert exit_code == 1
        assert any('time_wait' in w['message'].lower() for w in output.data['warnings'])

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds can be specified."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(
            file_contents={
                '/proc/net/sockstat': SOCKSTAT_HEALTHY,
                '/proc/net/sockstat6': SOCKSTAT6_EMPTY,
                '/proc/sys/net/ipv4/tcp_mem': TCP_MEM_NORMAL,
                '/proc/sys/net/ipv4/udp_mem': UDP_MEM_NORMAL,
            }
        )
        output = Output()

        exit_code = socket_buffer.run(['--warn', '50', '--crit', '70'], output, ctx)

        assert exit_code == 0

    def test_invalid_threshold_returns_error(self, mock_context):
        """Returns 2 for invalid threshold values."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(
            file_contents={
                '/proc/net/sockstat': SOCKSTAT_HEALTHY,
            }
        )
        output = Output()

        exit_code = socket_buffer.run(['--warn', '80', '--crit', '70'], output, ctx)

        assert exit_code == 2

    def test_verbose_output(self, mock_context):
        """--verbose flag works."""
        from scripts.baremetal import socket_buffer

        ctx = mock_context(
            file_contents={
                '/proc/net/sockstat': SOCKSTAT_HEALTHY,
                '/proc/net/sockstat6': SOCKSTAT6_EMPTY,
                '/proc/sys/net/ipv4/tcp_mem': TCP_MEM_NORMAL,
                '/proc/sys/net/ipv4/udp_mem': UDP_MEM_NORMAL,
            }
        )
        output = Output()

        exit_code = socket_buffer.run(['--verbose'], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
