"""Tests for k8s metrics_server script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_deployment(
    replicas: int = 1,
    ready_replicas: int = 1,
    available_replicas: int = 1,
) -> dict:
    """Create a mock metrics-server deployment."""
    return {
        "metadata": {
            "name": "metrics-server",
            "namespace": "kube-system",
        },
        "spec": {"replicas": replicas},
        "status": {
            "replicas": replicas,
            "readyReplicas": ready_replicas,
            "availableReplicas": available_replicas,
            "updatedReplicas": replicas,
        },
    }


def make_pod(
    name: str = "metrics-server-abc123",
    ready: bool = True,
    phase: str = "Running",
    restarts: int = 0,
) -> dict:
    """Create a mock metrics-server pod."""
    return {
        "metadata": {
            "name": name,
            "namespace": "kube-system",
        },
        "status": {
            "phase": phase,
            "containerStatuses": [
                {
                    "name": "metrics-server",
                    "ready": ready,
                    "restartCount": restarts,
                }
            ],
        },
    }


def make_api_service(available: bool = True) -> dict:
    """Create a mock API service."""
    return {
        "metadata": {"name": "v1beta1.metrics.k8s.io"},
        "status": {
            "conditions": [
                {
                    "type": "Available",
                    "status": "True" if available else "False",
                    "reason": "Passed" if available else "FailedDiscoveryCheck",
                    "message": "" if available else "no response from server",
                }
            ]
        },
    }


class TestMetricsServer:
    """Tests for metrics_server."""

    def test_healthy_metrics_server(self, capsys):
        """Healthy metrics server returns exit code 0."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%\nnode-2  200m  10%  2000Mi  20%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "All Metrics Server health checks passed" in captured.out

    def test_deployment_not_found(self, capsys):
        """Missing deployment returns exit code 1."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): KeyError(
                    "not found"
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): KeyError("not found"),
                ("kubectl", "top", "nodes", "--no-headers"): KeyError("failed"),
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): KeyError("failed"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "FAIL" in captured.out

    def test_replicas_not_ready(self, capsys):
        """Not ready replicas returns warnings."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment(replicas=2, ready_replicas=1)
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod(), make_pod(name="metrics-server-def456", ready=False)]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run([], output, context)

        # Should have issues due to not ready container
        assert result == 1
        captured = capsys.readouterr()
        assert "1/2" in captured.out or "not ready" in captured.out.lower()

    def test_api_service_unavailable(self, capsys):
        """Unavailable API service returns exit code 1."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service(available=False)
                ),
                ("kubectl", "top", "nodes", "--no-headers"): KeyError("failed"),
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): KeyError("failed"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.out.lower() or "UNAVAIL" in captured.out

    def test_pod_restarts(self, capsys):
        """Pod with many restarts generates warnings."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod(restarts=15)]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run([], output, context)

        # Warnings don't cause exit code 1, only issues do
        captured = capsys.readouterr()
        assert "restart" in captured.out.lower() or "15" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "deployment" in data
        assert "pods" in data
        assert "api_service" in data
        assert "metrics" in data
        assert "healthy" in data
        assert data["healthy"] is True

    def test_table_output(self, capsys):
        """Table output format works."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Component" in captured.out
        assert "Status" in captured.out
        assert "All checks passed" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_custom_namespace(self, capsys):
        """Custom namespace is used."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "monitoring", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "monitoring", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run(["--namespace", "monitoring"], output, context)

        assert result == 0

    def test_warn_only_suppresses_healthy(self, capsys):
        """Warn-only flag suppresses output when healthy."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Output should be empty when healthy and warn-only
        assert captured.out.strip() == ""

    def test_node_metrics_count(self, capsys):
        """Node metrics count is reported."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%\nnode-2  200m  10%  2000Mi  20%\nnode-3  150m  7%  1500Mi  15%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["metrics"]["nodes_reporting"] == 3

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.metrics_server import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "metrics-server", "-n", "kube-system", "-o", "json"): json.dumps(
                    make_deployment()
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=metrics-server", "-o", "json"): json.dumps(
                    {"items": [make_pod()]}
                ),
                ("kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"): json.dumps(
                    make_api_service()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node-1  100m  5%  1000Mi  10%",
                ("kubectl", "top", "pods", "--all-namespaces", "--no-headers"): "kube-system  pod-1  50m  100Mi",
            },
        )
        output = Output()

        run([], output, context)

        assert "issues=" in output.summary
        assert "warnings=" in output.summary
