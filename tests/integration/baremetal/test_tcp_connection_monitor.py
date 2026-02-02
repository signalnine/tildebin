"""Integration tests for tcp_connection_monitor script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestTcpConnectionMonitorIntegration:
    """Integration tests for tcp_connection_monitor on real hardware."""

    def test_tcp_connection_monitor_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import tcp_connection_monitor

        context = Context()
        result = tcp_connection_monitor.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import tcp_connection_monitor
        import json

        context = Context()
        tcp_connection_monitor.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
