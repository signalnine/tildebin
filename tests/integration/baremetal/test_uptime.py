"""Integration tests for uptime script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestUptimeIntegration:
    """Integration tests for uptime on real hardware."""

    def test_uptime_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import uptime

        context = Context()
        result = uptime.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import uptime
        import json

        context = Context()
        uptime.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
