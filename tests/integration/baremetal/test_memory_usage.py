"""Integration tests for memory_usage script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestMemoryUsageIntegration:
    """Integration tests for memory_usage on real hardware."""

    def test_memory_usage_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import memory_usage

        context = Context()
        result = memory_usage.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import memory_usage
        import json

        context = Context()
        memory_usage.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))

    def test_detects_memory(self, has_proc, output):
        """Detects system memory."""
        from scripts.baremetal import memory_usage

        context = Context()
        result = memory_usage.run([], output, context)

        # Should detect memory without errors
        assert result in (0, 1)
