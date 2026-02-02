"""Integration tests for entropy_monitor script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestEntropyMonitorIntegration:
    """Integration tests for entropy_monitor on real hardware."""

    def test_entropy_monitor_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import entropy_monitor

        context = Context()
        result = entropy_monitor.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import entropy_monitor
        import json

        context = Context()
        entropy_monitor.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
