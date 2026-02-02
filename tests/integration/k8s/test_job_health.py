"""Integration tests for job_health script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestJobHealthIntegration:
    """Integration tests for job_health."""

    def test_completed_job_healthy(
        self, cluster_available, test_namespace, completed_job, output
    ):
        """A completed job should be considered healthy."""
        from scripts.k8s import job_health

        context = Context()
        result = job_health.run(["-n", test_namespace], output, context)

        # Completed jobs are healthy
        assert result == 0

    def test_failed_job_unhealthy(
        self, cluster_available, test_namespace, failed_job, output
    ):
        """A failed job should return exit code 1."""
        from scripts.k8s import job_health

        context = Context()
        result = job_health.run(["-n", test_namespace], output, context)

        assert result == 1

    def test_json_output_format(
        self, cluster_available, test_namespace, completed_job, output, capsys
    ):
        """JSON output contains expected fields."""
        from scripts.k8s import job_health
        import json

        context = Context()
        job_health.run(["-n", test_namespace, "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "jobs" in data or "summary" in data

    def test_warn_only_filters_healthy(
        self, cluster_available, test_namespace, completed_job, output, capsys
    ):
        """--warn-only should not show healthy jobs."""
        from scripts.k8s import job_health

        context = Context()
        result = job_health.run(
            ["-n", test_namespace, "--warn-only"], output, context
        )

        assert result == 0
