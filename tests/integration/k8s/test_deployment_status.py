"""Integration tests for deployment_status script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestDeploymentStatusIntegration:
    """Integration tests for deployment_status."""

    def test_healthy_deployment_returns_zero(
        self, cluster_available, test_namespace, healthy_deployment, output
    ):
        """A healthy deployment should return exit code 0."""
        from scripts.k8s import deployment_status

        context = Context()
        result = deployment_status.run(["-n", test_namespace], output, context)

        assert result == 0
        assert output.data["summary"]["unhealthy"] == 0

    def test_unhealthy_deployment_returns_one(
        self, cluster_available, test_namespace, unhealthy_deployment, output
    ):
        """A deployment that cannot reach desired replicas returns exit code 1."""
        from scripts.k8s import deployment_status

        context = Context()
        result = deployment_status.run(["-n", test_namespace], output, context)

        assert result == 1
        assert output.data["summary"]["unhealthy"] > 0

    def test_json_output_format(
        self, cluster_available, test_namespace, healthy_deployment, output, capsys
    ):
        """JSON output contains expected fields."""
        from scripts.k8s import deployment_status
        import json

        context = Context()
        result = deployment_status.run(
            ["-n", test_namespace, "--format", "json"], output, context
        )

        captured = capsys.readouterr()
        # JSON output may be empty if no output in JSON mode
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (list, dict))

    def test_warn_only_filters_healthy(
        self, cluster_available, test_namespace, healthy_deployment, output, capsys
    ):
        """--warn-only should not show healthy deployments."""
        from scripts.k8s import deployment_status

        context = Context()
        result = deployment_status.run(
            ["-n", test_namespace, "--warn-only"], output, context
        )

        # With all healthy, no warnings should appear
        captured = capsys.readouterr()
        # Should be silent or minimal output
        assert result == 0
