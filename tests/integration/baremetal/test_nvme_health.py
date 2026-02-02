"""Integration tests for nvme_health script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestNvmeHealthIntegration:
    """Integration tests for nvme_health on real hardware."""

    def test_nvme_health_runs(self, has_nvme, output):
        """Script runs on system with NVMe drives."""
        from scripts.baremetal import nvme_health

        context = Context()
        result = nvme_health.run([], output, context)

        # May need nvme-cli tool
        assert result in (0, 1, 2)

    def test_json_output(self, has_nvme, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import nvme_health
        import json

        context = Context()
        nvme_health.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))
