"""Integration tests for process_tree script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestProcessTreeIntegration:
    """Integration tests for process_tree on real hardware."""

    def test_process_tree_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import process_tree

        context = Context()
        result = process_tree.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import process_tree
        import json

        context = Context()
        process_tree.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
