"""Integration tests for systemd_service_monitor script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestSystemdServiceMonitorIntegration:
    """Integration tests for systemd_service_monitor on real hardware."""

    def test_systemd_service_monitor_runs(self, has_systemd, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import systemd_service_monitor

        context = Context()
        result = systemd_service_monitor.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_systemd, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import systemd_service_monitor
        import json

        context = Context()
        systemd_service_monitor.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
