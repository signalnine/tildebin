"""Integration tests for load_average script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestLoadAverageIntegration:
    """Integration tests for load_average on real hardware."""

    def test_load_average_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import load_average

        context = Context()
        result = load_average.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import load_average
        import json

        context = Context()
        load_average.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
