"""Integration tests for cpu_usage script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestCpuUsageIntegration:
    """Integration tests for cpu_usage on real hardware."""

    def test_cpu_usage_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import cpu_usage

        context = Context()
        result = cpu_usage.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import cpu_usage
        import json

        context = Context()
        cpu_usage.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))

    def test_verbose_mode(self, has_proc, output):
        """Verbose mode works."""
        from scripts.baremetal import cpu_usage

        context = Context()
        result = cpu_usage.run(["-v"], output, context)

        assert result in (0, 1)
