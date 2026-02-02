"""Integration tests for swap_monitor script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestSwapMonitorIntegration:
    """Integration tests for swap_monitor on real hardware."""

    def test_swap_monitor_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import swap_monitor

        context = Context()
        result = swap_monitor.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import swap_monitor
        import json

        context = Context()
        swap_monitor.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
