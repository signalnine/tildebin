"""Integration tests for thermal_zone script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestThermalZoneIntegration:
    """Integration tests for thermal_zone on real hardware."""

    def test_thermal_zone_runs(self, has_thermal, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import thermal_zone

        context = Context()
        result = thermal_zone.run([], output, context)

        # Exit 2 may occur if required tool is missing
        assert result in (0, 1, 2)

    def test_json_output(self, has_thermal, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import thermal_zone
        import json

        context = Context()
        thermal_zone.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))

    def test_verbose_mode(self, has_thermal, output):
        """Verbose mode works."""
        from scripts.baremetal import thermal_zone

        context = Context()
        result = thermal_zone.run(["-v"], output, context)

        # Exit 2 may occur if required tool is missing
        assert result in (0, 1, 2)
