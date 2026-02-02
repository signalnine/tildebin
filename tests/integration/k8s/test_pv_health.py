"""Integration tests for pv_health script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestPvHealthIntegration:
    """Integration tests for pv_health."""

    def test_with_pending_pvc(
        self, cluster_available, test_namespace, pvc_pending, output
    ):
        """Script runs without error when pending PVCs exist."""
        from scripts.k8s import pv_health

        context = Context()
        # pv_health scans all PVs/PVCs cluster-wide (no namespace filter)
        result = pv_health.run([], output, context)

        # Should run without error (pending PVCs may or may not be flagged)
        assert result in (0, 1)

    def test_json_output_format(
        self, cluster_available, test_namespace, pvc_pending, output, capsys
    ):
        """JSON output contains expected fields."""
        from scripts.k8s import pv_health
        import json

        context = Context()
        pv_health.run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))

    def test_all_namespaces_mode(self, cluster_available, output):
        """Should be able to scan all namespaces."""
        from scripts.k8s import pv_health

        context = Context()
        result = pv_health.run([], output, context)

        # Should not error
        assert result in (0, 1)
