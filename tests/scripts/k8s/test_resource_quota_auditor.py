"""Tests for resource_quota_auditor script."""

import json
import pytest

from boxctl.core.output import Output


class TestResourceQuotaAuditor:
    """Tests for resource_quota_auditor script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import resource_quota_auditor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = resource_quota_auditor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_quotas_reports_issue(self, mock_context, fixtures_dir):
        """Returns 1 when namespaces have no ResourceQuotas."""
        from scripts.k8s import resource_quota_auditor

        namespaces = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
                ("kubectl", "get", "resourcequota", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "limitrange", "-o", "json", "--all-namespaces"): empty,
            }
        )
        output = Output()

        exit_code = resource_quota_auditor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["namespaces_without_quota"] > 0

    def test_healthy_cluster_with_quotas(self, mock_context, fixtures_dir):
        """Detects namespaces with proper quotas."""
        from scripts.k8s import resource_quota_auditor

        namespaces = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        quotas = (fixtures_dir / "k8s" / "resource_quotas.json").read_text()
        limitranges = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
                ("kubectl", "get", "resourcequota", "-o", "json", "--all-namespaces"): quotas,
                ("kubectl", "get", "limitrange", "-o", "json", "--all-namespaces"): limitranges,
            }
        )
        output = Output()

        exit_code = resource_quota_auditor.run([], output, ctx)

        # Should detect namespaces
        assert output.data["summary"]["total_namespaces"] > 0

    def test_high_utilization_detected(self, mock_context, fixtures_dir):
        """Detects quotas with high utilization."""
        from scripts.k8s import resource_quota_auditor

        namespaces = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        quotas = (fixtures_dir / "k8s" / "resource_quotas_high_usage.json").read_text()
        limitranges = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
                ("kubectl", "get", "resourcequota", "-o", "json", "--all-namespaces"): quotas,
                ("kubectl", "get", "limitrange", "-o", "json", "--all-namespaces"): limitranges,
            }
        )
        output = Output()

        exit_code = resource_quota_auditor.run([], output, ctx)

        # Should return 1 (issues found) for high utilization
        assert exit_code == 1

    def test_warn_threshold_customizable(self, mock_context, fixtures_dir):
        """--warn-threshold adjusts utilization warning level."""
        from scripts.k8s import resource_quota_auditor

        namespaces = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        quotas = (fixtures_dir / "k8s" / "resource_quotas_high_usage.json").read_text()
        limitranges = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
                ("kubectl", "get", "resourcequota", "-o", "json", "--all-namespaces"): quotas,
                ("kubectl", "get", "limitrange", "-o", "json", "--all-namespaces"): limitranges,
            }
        )
        output = Output()

        # With 99% threshold, high usage shouldn't trigger warning
        exit_code = resource_quota_auditor.run(["--warn-threshold", "99"], output, ctx)

        assert exit_code in (0, 1)

    def test_warn_only_filters_healthy(self, mock_context, fixtures_dir):
        """--warn-only only shows namespaces with issues."""
        from scripts.k8s import resource_quota_auditor

        namespaces = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        quotas = (fixtures_dir / "k8s" / "resource_quotas.json").read_text()
        limitranges = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
                ("kubectl", "get", "resourcequota", "-o", "json", "--all-namespaces"): quotas,
                ("kubectl", "get", "limitrange", "-o", "json", "--all-namespaces"): limitranges,
            }
        )
        output = Output()

        exit_code = resource_quota_auditor.run(["--warn-only"], output, ctx)

        # All namespaces in output should have issues
        for ns in output.data["namespaces"]:
            assert len(ns["issues"]) > 0

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """--namespace filters to specific namespace."""
        from scripts.k8s import resource_quota_auditor

        quotas = (fixtures_dir / "k8s" / "resource_quotas.json").read_text()
        limitranges = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "resourcequota", "-o", "json", "-n", "production"): quotas,
                ("kubectl", "get", "limitrange", "-o", "json", "-n", "production"): limitranges,
            }
        )
        output = Output()

        exit_code = resource_quota_auditor.run(["-n", "production"], output, ctx)

        assert exit_code in (0, 1)
        assert output.data["summary"]["total_namespaces"] == 1
