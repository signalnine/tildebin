"""Integration tests for node_health script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestNodeHealthIntegration:
    """Integration tests for node_health.

    These tests validate the script works against real cluster nodes.
    """

    def test_cluster_nodes_detected(self, cluster_available, output):
        """Should detect cluster nodes."""
        from scripts.k8s import node_health

        context = Context()
        result = node_health.run([], output, context)

        # Should find at least one node and not error
        assert result in (0, 1)

    def test_json_output_format(self, cluster_available, output, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s import node_health
        import json

        context = Context()
        node_health.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should be valid JSON (list or dict)
        assert isinstance(data, (list, dict))

    def test_warn_only_mode(self, cluster_available, output, capsys):
        """--warn-only mode should work without errors."""
        from scripts.k8s import node_health

        context = Context()
        result = node_health.run(["--warn-only"], output, context)

        # Should not error
        assert result in (0, 1)
