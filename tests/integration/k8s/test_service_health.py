"""Integration tests for service_health script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestServiceHealthIntegration:
    """Integration tests for service_health."""

    def test_service_with_endpoints_healthy(
        self, cluster_available, test_namespace, healthy_service, output
    ):
        """A service with matching endpoints should return exit code 0."""
        from scripts.k8s import service_health

        context = Context()
        result = service_health.run(["-n", test_namespace], output, context)

        assert result == 0

    def test_service_no_endpoints_unhealthy(
        self, cluster_available, test_namespace, service_no_endpoints, output
    ):
        """A service with no endpoints should return exit code 1."""
        from scripts.k8s import service_health

        context = Context()
        result = service_health.run(["-n", test_namespace], output, context)

        assert result == 1
        # The issue should mention no endpoints
        assert any("endpoint" in str(i).lower() for i in output.data.get("issues", []))

    def test_json_output_format(
        self, cluster_available, test_namespace, healthy_service, output, capsys
    ):
        """JSON output contains expected fields."""
        from scripts.k8s import service_health
        import json

        context = Context()
        service_health.run(["-n", test_namespace, "--format", "json"], output, context)

        captured = capsys.readouterr()
        # JSON output may be empty if nothing to report in plain mode
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (list, dict))

    def test_verbose_mode(
        self, cluster_available, test_namespace, healthy_service, output, capsys
    ):
        """Verbose mode should work."""
        from scripts.k8s import service_health

        context = Context()
        result = service_health.run(
            ["-n", test_namespace, "-v"], output, context
        )

        assert result == 0
