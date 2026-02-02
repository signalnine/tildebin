"""Integration tests for disk_health script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestDiskHealthIntegration:
    """Integration tests for disk_health on real hardware."""

    def test_disk_health_runs(self, has_block_devices, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import disk_health

        context = Context()
        result = disk_health.run([], output, context)

        # May return 1 if no SMART data available (no smartctl)
        assert result in (0, 1, 2)

    def test_json_output(self, has_block_devices, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import disk_health
        import json

        context = Context()
        disk_health.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
