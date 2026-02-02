"""Tests for k8s hpa_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_hpa(
    name: str,
    namespace: str = "default",
    current_replicas: int = 2,
    desired_replicas: int = 2,
    min_replicas: int = 1,
    max_replicas: int = 10,
    conditions: list | None = None,
    current_metrics: list | None = None,
) -> dict:
    """Create an HPA for testing."""
    if conditions is None:
        conditions = [
            {"type": "ScalingActive", "status": "True"},
            {"type": "AbleToScale", "status": "True"},
        ]

    if current_metrics is None:
        current_metrics = [
            {
                "type": "Resource",
                "resource": {
                    "name": "cpu",
                    "current": {"averageUtilization": 50, "averageValue": "100m"},
                },
            }
        ]

    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "minReplicas": min_replicas,
            "maxReplicas": max_replicas,
            "scaleTargetRef": {"kind": "Deployment", "name": f"{name}-deployment"},
            "metrics": [
                {
                    "type": "Resource",
                    "resource": {
                        "name": "cpu",
                        "target": {"type": "Utilization", "averageUtilization": 80},
                    },
                }
            ],
        },
        "status": {
            "currentReplicas": current_replicas,
            "desiredReplicas": desired_replicas,
            "conditions": conditions,
            "currentMetrics": current_metrics,
        },
    }


def make_metrics_server_deployment(available: int = 1, desired: int = 1) -> dict:
    """Create a metrics-server deployment for testing."""
    return {
        "spec": {"replicas": desired},
        "status": {"availableReplicas": available},
    }


class TestHpaHealth:
    """Tests for hpa_health."""

    def test_healthy_hpas(self, capsys):
        """Healthy HPAs return exit code 0."""
        from scripts.k8s.hpa_health import run

        hpas = {"items": [make_hpa("hpa-1"), make_hpa("hpa-2")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_hpa_scaling_inactive(self, capsys):
        """HPA with inactive scaling returns exit code 1."""
        from scripts.k8s.hpa_health import run

        conditions = [
            {
                "type": "ScalingActive",
                "status": "False",
                "reason": "FailedGetResourceMetric",
                "message": "unable to get metrics",
            },
            {"type": "AbleToScale", "status": "True"},
        ]
        hpas = {"items": [make_hpa("hpa-1", conditions=conditions)]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Scaling inactive" in captured.out

    def test_hpa_no_metrics(self, capsys):
        """HPA with no metrics returns exit code 1."""
        from scripts.k8s.hpa_health import run

        hpas = {"items": [make_hpa("hpa-1", current_metrics=[])]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "No current metrics available" in captured.out

    def test_hpa_at_max_replicas(self, capsys):
        """HPA at max replicas with scaling limited is flagged."""
        from scripts.k8s.hpa_health import run

        conditions = [
            {"type": "ScalingActive", "status": "True"},
            {"type": "AbleToScale", "status": "True"},
            {
                "type": "ScalingLimited",
                "status": "True",
                "message": "the desired count is maximum replica count",
            },
        ]
        hpas = {
            "items": [
                make_hpa(
                    "hpa-1",
                    current_replicas=10,
                    desired_replicas=10,
                    max_replicas=10,
                    conditions=conditions,
                )
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "maximum" in captured.out.lower() or "max replicas" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.hpa_health import run

        hpas = {"items": [make_hpa("hpa-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "metrics_server" in data
        assert "summary" in data
        assert "hpas" in data
        assert len(data["hpas"]) == 1
        assert data["hpas"][0]["name"] == "hpa-1"

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.hpa_health import run

        hpas = {"items": [make_hpa("hpa-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out
        assert "NAME" in captured.out
        assert "STATUS" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter works correctly."""
        from scripts.k8s.hpa_health import run

        hpas = {"items": [make_hpa("hpa-1", namespace="production")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "-n", "production"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "production/hpa-1" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy HPAs."""
        from scripts.k8s.hpa_health import run

        hpas = {
            "items": [
                make_hpa("healthy-hpa"),
                make_hpa("unhealthy-hpa", current_metrics=[]),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "unhealthy-hpa" in captured.out

    def test_metrics_server_unhealthy(self, capsys):
        """Unhealthy metrics server returns exit code 1."""
        from scripts.k8s.hpa_health import run

        hpas = {"items": [make_hpa("hpa-1")]}

        # Metrics server has 0 available replicas
        metrics_deployment = make_metrics_server_deployment(available=0, desired=1)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    metrics_deployment
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "",  # Fails
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        result = run([], output, context)

        # Should fail because metrics server is unhealthy
        assert result == 1
        captured = capsys.readouterr()
        assert "UNHEALTHY" in captured.out or "NOT DEPLOYED" in captured.out

    def test_no_hpas(self, capsys):
        """No HPAs returns exit code 0 if metrics server is healthy."""
        from scripts.k8s.hpa_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No HPAs found" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.hpa_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.hpa_health import run

        hpas = {"items": [make_hpa("hpa-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployment", "-n", "kube-system", "metrics-server", "-o", "json"): json.dumps(
                    make_metrics_server_deployment()
                ),
                ("kubectl", "top", "nodes", "--no-headers"): "node1  100m  10%  512Mi  5%\n",
                ("kubectl", "get", "hpa", "-o", "json", "--all-namespaces"): json.dumps(hpas),
            },
        )
        output = Output()

        run([], output, context)

        assert "hpas=" in output.summary
        assert "healthy=" in output.summary
        assert "metrics_server=" in output.summary
