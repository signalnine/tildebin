"""Integration tests for kernel_taint script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestKernelTaintIntegration:
    """Integration tests for kernel_taint on real hardware."""

    def test_kernel_taint_runs(self, has_proc, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import kernel_taint

        context = Context()
        result = kernel_taint.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_proc, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import kernel_taint
        import json

        context = Context()
        kernel_taint.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
