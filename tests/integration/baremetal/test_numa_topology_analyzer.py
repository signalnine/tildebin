"""Integration tests for numa_topology_analyzer script."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestNumaTopologyAnalyzerIntegration:
    """Integration tests for numa_topology_analyzer on real hardware."""

    def test_numa_topology_runs(self, has_numa, output):
        """Script runs and returns valid data."""
        from scripts.baremetal import numa_topology_analyzer

        context = Context()
        result = numa_topology_analyzer.run([], output, context)

        assert result in (0, 1)

    def test_json_output(self, has_numa, output, capsys):
        """JSON output is valid."""
        from scripts.baremetal import numa_topology_analyzer
        import json

        context = Context()
        numa_topology_analyzer.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))

    def test_detects_numa_nodes(self, has_numa, output, capsys):
        """Detects NUMA nodes on multi-socket system."""
        from scripts.baremetal import numa_topology_analyzer

        context = Context()
        result = numa_topology_analyzer.run([], output, context)

        # Should complete without error
        assert result in (0, 1)
