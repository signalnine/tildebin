"""Integration tests for filesystem_usage script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestFilesystemUsageIntegration:
    """Integration tests for filesystem_usage on real hardware."""

    def test_filesystem_usage_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import filesystem_usage

        context = Context()
        result = filesystem_usage.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import filesystem_usage
        import json

        context = Context()
        filesystem_usage.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))

    def test_verbose_mode(self, has_proc, output):
        """Verbose mode works."""
        from scripts.baremetal import filesystem_usage

        context = Context()
        result = filesystem_usage.run(["-v"], output, context)

        assert result in (0, 1)
