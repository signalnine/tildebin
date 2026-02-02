"""Integration tests for inode_usage script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestInodeUsageIntegration:
    """Integration tests for inode_usage on real hardware."""

    def test_inode_usage_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import inode_usage

        context = Context()
        result = inode_usage.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import inode_usage
        import json

        context = Context()
        inode_usage.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
