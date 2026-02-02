"""Tests for socket_queue script."""

import pytest

from boxctl.core.output import Output


SS_HEADER = "State      Recv-Q Send-Q Local Address:Port   Peer Address:Port\n"

SS_HEALTHY = SS_HEADER + """LISTEN     0      128    0.0.0.0:22      0.0.0.0:*
ESTAB      0      0      192.168.1.1:22      192.168.1.2:54321
ESTAB      0      0      192.168.1.1:80      192.168.1.3:54322
"""

SS_HIGH_RECV = SS_HEADER + """LISTEN     0      128    0.0.0.0:22      0.0.0.0:*
ESTAB      2097152 0      192.168.1.1:22      192.168.1.2:54321
"""

SS_HIGH_SEND = SS_HEADER + """LISTEN     0      128    0.0.0.0:22      0.0.0.0:*
ESTAB      0      5242880 192.168.1.1:22      192.168.1.2:54321
"""

SS_HIGH_BACKLOG = SS_HEADER + """LISTEN     500    128    0.0.0.0:22      0.0.0.0:*
ESTAB      0      0      192.168.1.1:22      192.168.1.2:54321
"""

SS_CRITICAL_BACKLOG = SS_HEADER + """LISTEN     2000   128    0.0.0.0:80      0.0.0.0:*
ESTAB      0      0      192.168.1.1:80      192.168.1.2:54321
"""

SS_WITH_PROCESS = SS_HEADER + """LISTEN     0      128    0.0.0.0:22      0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
ESTAB      0      0      192.168.1.1:22      192.168.1.2:54321  users:(("sshd",pid=1235,fd=4))
"""

SS_EMPTY = SS_HEADER


class TestSocketQueue:
    """Tests for socket_queue script."""

    def test_missing_ss_returns_error(self, mock_context):
        """Returns exit code 2 when ss not available."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = socket_queue.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("ss" in e.lower() for e in output.errors)

    def test_healthy_sockets(self, mock_context):
        """Returns 0 when all socket queues are healthy."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_HEALTHY,
            }
        )
        output = Output()

        exit_code = socket_queue.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'
        assert output.data['summary']['critical_count'] == 0
        assert output.data['summary']['warning_count'] == 0

    def test_high_recv_queue_warning(self, mock_context):
        """Returns 1 when receive queue exceeds warning threshold."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_HIGH_RECV,
            }
        )
        output = Output()

        exit_code = socket_queue.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] in ['warning', 'critical']

    def test_high_send_queue_warning(self, mock_context):
        """Returns 1 when send queue exceeds warning threshold."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_HIGH_SEND,
            }
        )
        output = Output()

        exit_code = socket_queue.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] in ['warning', 'critical']

    def test_high_listen_backlog_warning(self, mock_context):
        """Returns 1 when listen backlog exceeds warning threshold."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_HIGH_BACKLOG,
            }
        )
        output = Output()

        exit_code = socket_queue.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['warning_count'] > 0

    def test_critical_listen_backlog(self, mock_context):
        """Returns 1 with critical status when backlog exceeds critical threshold."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_CRITICAL_BACKLOG,
            }
        )
        output = Output()

        exit_code = socket_queue.run([], output, ctx)

        assert exit_code == 1
        assert output.data['status'] == 'critical'
        assert output.data['summary']['critical_count'] > 0

    def test_no_sockets(self, mock_context):
        """Returns 0 when no sockets found."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_EMPTY,
            }
        )
        output = Output()

        exit_code = socket_queue.run([], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'ok'

    def test_udp_protocol(self, mock_context):
        """UDP protocol can be specified."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-u"): SS_HEALTHY,
            }
        )
        output = Output()

        exit_code = socket_queue.run(["--protocol", "udp"], output, ctx)

        assert exit_code == 0

    def test_all_protocols(self, mock_context):
        """All protocols can be specified."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_HEALTHY,
                ("ss", "-n", "-a", "-e", "-p", "-u"): SS_HEALTHY,
            }
        )
        output = Output()

        exit_code = socket_queue.run(["--protocol", "all"], output, ctx)

        assert exit_code == 0

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds can be specified."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_HEALTHY,
            }
        )
        output = Output()

        exit_code = socket_queue.run([
            "--recv-warn", "500000",
            "--recv-crit", "1000000",
        ], output, ctx)

        assert exit_code == 0

    def test_invalid_threshold_returns_error(self, mock_context):
        """Returns 2 for invalid threshold values."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(tools_available=["ss"])
        output = Output()

        exit_code = socket_queue.run([
            "--recv-warn", "1000000",
            "--recv-crit", "500000",
        ], output, ctx)

        assert exit_code == 2

    def test_verbose_includes_process_stats(self, mock_context):
        """--verbose includes process statistics."""
        from scripts.baremetal import socket_queue

        ctx = mock_context(
            tools_available=["ss"],
            command_outputs={
                ("ss", "-n", "-a", "-e", "-p", "-t"): SS_WITH_PROCESS,
            }
        )
        output = Output()

        exit_code = socket_queue.run(["--verbose"], output, ctx)

        assert exit_code == 0
