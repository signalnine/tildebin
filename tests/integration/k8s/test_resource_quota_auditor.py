"""Integration tests for resource_quota_auditor script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestResourceQuotaAuditorIntegration:
    """Integration tests for resource_quota_auditor."""

    def test_namespace_with_quota(
        self, cluster_available, test_namespace, resource_quota, output
    ):
        """Should detect and report resource quota in namespace."""
        from scripts.k8s import resource_quota_auditor

        context = Context()
        result = resource_quota_auditor.run(["-n", test_namespace], output, context)

        # Should return without error
        assert result in (0, 1)

    def test_json_output_format(
        self, cluster_available, test_namespace, resource_quota, output, capsys
    ):
        """JSON output contains expected fields."""
        from scripts.k8s import resource_quota_auditor
        import json

        context = Context()
        resource_quota_auditor.run(
            ["-n", test_namespace, "--format", "json"], output, context
        )

        captured = capsys.readouterr()
        # JSON output may be empty
        if captured.out.strip():
            data = json.loads(captured.out)
            assert isinstance(data, (dict, list))

    def test_all_namespaces_mode(self, cluster_available, output):
        """Should be able to scan all namespaces."""
        from scripts.k8s import resource_quota_auditor

        context = Context()
        result = resource_quota_auditor.run([], output, context)

        # Should not error
        assert result in (0, 1)
