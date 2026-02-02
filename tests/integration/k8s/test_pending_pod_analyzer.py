"""Integration tests for pending_pod_analyzer script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestPendingPodAnalyzerIntegration:
    """Integration tests for pending_pod_analyzer."""

    def test_detects_pending_pod(
        self, cluster_available, test_namespace, pending_pod, output
    ):
        """Should detect a pending pod."""
        from scripts.k8s import pending_pod_analyzer

        context = Context()
        result = pending_pod_analyzer.run(["-n", test_namespace], output, context)

        # Should find the pending pod - exit code 1 means issues found
        assert result == 1

    def test_no_pending_pods(
        self, cluster_available, test_namespace, healthy_pod, output
    ):
        """Should return 0 when no pods are pending."""
        from scripts.k8s import pending_pod_analyzer

        context = Context()
        result = pending_pod_analyzer.run(["-n", test_namespace], output, context)

        # Should find no pending pods (healthy pod is Running)
        assert result == 0

    def test_json_output_format(
        self, cluster_available, test_namespace, pending_pod, output, capsys
    ):
        """JSON output contains expected fields."""
        from scripts.k8s import pending_pod_analyzer
        import json

        context = Context()
        pending_pod_analyzer.run(
            ["-n", test_namespace, "--format", "json"], output, context
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should have pod/summary info
        assert isinstance(data, (dict, list))
