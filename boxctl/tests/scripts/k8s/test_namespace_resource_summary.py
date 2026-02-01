"""Tests for namespace_resource_summary script."""

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
def empty_pods():
    """Empty pod list."""
    return json.dumps({"apiVersion": "v1", "kind": "PodList", "items": []})


@pytest.fixture
def pods_system_ns():
    """Pods in system namespaces."""
    return json.dumps({
        "apiVersion": "v1",
        "kind": "PodList",
        "items": [
            {
                "metadata": {"name": "coredns-abc", "namespace": "kube-system"},
                "spec": {"containers": [{"name": "coredns", "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}}}]},
                "status": {"phase": "Running"}
            },
            {
                "metadata": {"name": "app-xyz", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "resources": {"requests": {"cpu": "200m", "memory": "256Mi"}}}]},
                "status": {"phase": "Running"}
            }
        ]
    })


class TestNamespaceResourceSummary:
    """Tests for namespace_resource_summary script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = namespace_resource_summary.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_empty_cluster_no_pods(self, mock_context, empty_pods):
        """Returns 0 with warning when no pods found."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): empty_pods,
            }
        )
        output = Output()

        exit_code = namespace_resource_summary.run([], output, ctx)

        assert exit_code == 0
        assert len(output.warnings) > 0
        assert output.data["namespaces"] == []

    def test_aggregates_resources_by_namespace(self, mock_context, pods_with_resources):
        """Correctly aggregates resources by namespace."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
            }
        )
        output = Output()

        exit_code = namespace_resource_summary.run([], output, ctx)

        assert "namespaces" in output.data
        assert "cluster_totals" in output.data

        # Find production namespace
        prod_ns = next((n for n in output.data["namespaces"] if n["namespace"] == "production"), None)
        assert prod_ns is not None
        assert prod_ns["pod_count"] == 2  # nginx + api-server
        assert prod_ns["container_count"] == 3  # nginx(1) + api-server(2)

    def test_filters_system_namespaces_by_default(self, mock_context, pods_system_ns):
        """System namespaces are filtered out by default."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_system_ns,
            }
        )
        output = Output()

        exit_code = namespace_resource_summary.run([], output, ctx)

        ns_names = [n["namespace"] for n in output.data["namespaces"]]
        assert "kube-system" not in ns_names
        assert "default" in ns_names

    def test_show_all_includes_system_namespaces(self, mock_context, pods_system_ns):
        """--all includes system namespaces."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_system_ns,
            }
        )
        output = Output()

        exit_code = namespace_resource_summary.run(["--all"], output, ctx)

        ns_names = [n["namespace"] for n in output.data["namespaces"]]
        assert "kube-system" in ns_names
        assert "default" in ns_names

    def test_sort_by_memory(self, mock_context, pods_with_resources):
        """--sort memory sorts by memory requests descending."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
            }
        )
        output = Output()

        exit_code = namespace_resource_summary.run(["--sort", "memory"], output, ctx)

        namespaces = output.data["namespaces"]
        # Verify sorted by memory descending
        for i in range(len(namespaces) - 1):
            assert namespaces[i]["memory_requests_bytes"] >= namespaces[i + 1]["memory_requests_bytes"]

    def test_verbose_includes_efficiency(self, mock_context, pods_with_resources):
        """--verbose includes efficiency ratios."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): pods_with_resources,
            }
        )
        output = Output()

        exit_code = namespace_resource_summary.run(["--verbose"], output, ctx)

        # Find a namespace with pods
        ns_with_pods = [n for n in output.data["namespaces"] if n["pod_count"] > 0]
        assert len(ns_with_pods) > 0
        assert "cpu_req_limit_ratio" in ns_with_pods[0]
        assert "memory_req_limit_ratio" in ns_with_pods[0]

    def test_invalid_threshold_returns_error(self, mock_context):
        """Invalid --req-limit-threshold returns exit code 2."""
        from scripts.k8s import namespace_resource_summary

        ctx = mock_context(tools_available=["kubectl"])
        output = Output()

        exit_code = namespace_resource_summary.run(["--req-limit-threshold", "150"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
