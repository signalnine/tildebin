"""Integration tests for daemonset_health script against a real Kubernetes cluster."""

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


@pytest.mark.integration
class TestDaemonsetHealthIntegration:
    """Integration tests for daemonset_health.

    Note: DaemonSet tests are limited because we can't easily create
    unhealthy DaemonSets in a test cluster without node manipulation.
    We primarily test the script interface works against real resources.
    """

    def test_system_daemonsets(self, cluster_available, output):
        """Should be able to check system DaemonSets (kube-system)."""
        from scripts.k8s import daemonset_health

        context = Context()
        # kube-system usually has DaemonSets like kube-proxy, calico, etc.
        result = daemonset_health.run(["-n", "kube-system"], output, context)

        # Should return 0 or 1, not 2 (error)
        assert result in (0, 1)

    def test_json_output_format(self, cluster_available, output, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s import daemonset_health
        import json

        context = Context()
        daemonset_health.run(
            ["-n", "kube-system", "--format", "json"], output, context
        )

        captured = capsys.readouterr()
        # Only check if we got valid JSON
        data = json.loads(captured.out)
        assert isinstance(data, (dict, list))

    def test_warn_only_mode(self, cluster_available, output, capsys):
        """--warn-only mode should work without errors."""
        from scripts.k8s import daemonset_health

        context = Context()
        result = daemonset_health.run(
            ["-n", "kube-system", "--warn-only"], output, context
        )

        # Should not error
        assert result in (0, 1)
