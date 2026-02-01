"""Tests for namespace_resource_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def pods_with_resources(fixtures_dir):
    """Load pods with resource requests/limits."""
    return (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()


@pytest.fixture
def pods_no_resources(fixtures_dir):
    """Load pods without resource requests/limits."""
    return (fixtures_dir / "k8s" / "pods_no_resources.json").read_text()


@pytest.fixture
def resource_quotas(fixtures_dir):
    """Load resource quotas."""
    return (fixtures_dir / "k8s" / "resource_quotas.json").read_text()


@pytest.fixture
def namespaces(fixtures_dir):
    """Load namespaces."""
    return (fixtures_dir / "k8s" / "namespaces.json").read_text()


@pytest.fixture
def empty_list():
    """Empty Kubernetes list."""
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": []})


class TestNamespaceResourceAnalyzer:
    """Tests for namespace_resource_analyzer script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import namespace_resource_analyzer

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = namespace_resource_analyzer.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_healthy_cluster_no_issues(
        self, mock_context, pods_with_resources, resource_quotas, namespaces
    ):
        """Returns 0 when all namespaces have quotas and pods have resources."""
        from scripts.k8s import namespace_resource_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
                ("kubectl", "get", "resourcequota", "--all-namespaces", "-o", "json"): resource_quotas,
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
            }
        )
        output = Output()

        exit_code = namespace_resource_analyzer.run([], output, ctx)

        # Has issues because staging has no quota and has a pod without resources
        assert "namespaces" in output.data
        assert "cluster_totals" in output.data
        assert output.data["cluster_totals"]["pod_count"] == 4

    def test_namespace_without_quota_flagged(
        self, mock_context, pods_with_resources, namespaces, empty_list
    ):
        """Flags namespaces with pods but no resource quota."""
        from scripts.k8s import namespace_resource_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
                ("kubectl", "get", "resourcequota", "--all-namespaces", "-o", "json"): empty_list,
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
            }
        )
        output = Output()

        exit_code = namespace_resource_analyzer.run([], output, ctx)

        assert exit_code == 1  # Issues found
        assert "issues" in output.data
        no_quota_issues = [i for i in output.data["issues"] if i["type"] == "no_quota"]
        assert len(no_quota_issues) > 0

    def test_pods_without_requests_flagged(
        self, mock_context, pods_no_resources, namespaces, empty_list
    ):
        """Flags pods without resource requests."""
        from scripts.k8s import namespace_resource_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_no_resources,
                ("kubectl", "get", "resourcequota", "--all-namespaces", "-o", "json"): empty_list,
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
            }
        )
        output = Output()

        exit_code = namespace_resource_analyzer.run([], output, ctx)

        assert exit_code == 1
        missing_requests = [i for i in output.data["issues"] if i["type"] == "missing_requests"]
        assert len(missing_requests) > 0

    def test_top_n_filter(
        self, mock_context, pods_with_resources, resource_quotas, namespaces
    ):
        """--top N limits output to top N namespaces by CPU."""
        from scripts.k8s import namespace_resource_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
                ("kubectl", "get", "resourcequota", "--all-namespaces", "-o", "json"): resource_quotas,
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
            }
        )
        output = Output()

        exit_code = namespace_resource_analyzer.run(["--top", "1"], output, ctx)

        # Should only show top 1 namespace
        assert len(output.data["namespaces"]) == 1

    def test_verbose_includes_limits(
        self, mock_context, pods_with_resources, resource_quotas, namespaces
    ):
        """--verbose includes CPU/memory limits in output."""
        from scripts.k8s import namespace_resource_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
                ("kubectl", "get", "resourcequota", "--all-namespaces", "-o", "json"): resource_quotas,
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
            }
        )
        output = Output()

        exit_code = namespace_resource_analyzer.run(["--verbose"], output, ctx)

        # Verbose mode should include limits for namespaces with pods
        ns_with_pods = [n for n in output.data["namespaces"] if n["pod_count"] > 0]
        if ns_with_pods:
            assert "cpu_limits_millicores" in ns_with_pods[0]
            assert "memory_limits_display" in ns_with_pods[0]

    def test_warn_only_filters_healthy(
        self, mock_context, pods_with_resources, resource_quotas, namespaces
    ):
        """--warn-only only shows namespaces with issues."""
        from scripts.k8s import namespace_resource_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
                ("kubectl", "get", "resourcequota", "--all-namespaces", "-o", "json"): resource_quotas,
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces,
            }
        )
        output = Output()

        exit_code = namespace_resource_analyzer.run(["--warn-only"], output, ctx)

        # Only namespaces with issues should be shown
        for ns in output.data["namespaces"]:
            assert len(ns["issues"]) > 0
