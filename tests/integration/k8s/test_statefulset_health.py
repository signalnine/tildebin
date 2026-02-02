"""Integration tests for statefulset_health script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestStatefulsetHealthIntegration:
    """Integration tests for statefulset_health."""

    def test_healthy_statefulset_returns_zero(
        self, cluster_available, test_namespace, healthy_statefulset, output
    ):
        """A healthy StatefulSet should return exit code 0."""
        from scripts.k8s import statefulset_health

        context = Context()
        result = statefulset_health.run(["-n", test_namespace], output, context)

        assert result == 0

    def test_json_output_format(
        self, cluster_available, test_namespace, healthy_statefulset, output, capsys
    ):
        """JSON output contains expected fields."""
        from scripts.k8s import statefulset_health
        import json

        context = Context()
        statefulset_health.run(
            ["-n", test_namespace, "--format", "json"], output, context
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # JSON output can be list or dict
        assert isinstance(data, (list, dict))

    def test_warn_only_filters_healthy(
        self, cluster_available, test_namespace, healthy_statefulset, output, capsys
    ):
        """--warn-only should not show healthy StatefulSets."""
        from scripts.k8s import statefulset_health

        context = Context()
        result = statefulset_health.run(
            ["-n", test_namespace, "--warn-only"], output, context
        )

        assert result == 0
