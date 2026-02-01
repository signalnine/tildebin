"""Tests for pod_eviction_risk_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestPodEvictionRiskAnalyzer:
    """Tests for pod_eviction_risk_analyzer."""

    def test_no_pods(self, capsys):
        """No pods returns exit code 0."""
        from scripts.k8s.pod_eviction_risk_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_empty.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_pods_at_risk(self, capsys):
        """Pods at risk returns exit code 1."""
        from scripts.k8s.pod_eviction_risk_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_eviction_risk.json"
                ),
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_with_pressure.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out or "besteffort" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.pod_eviction_risk_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_eviction_risk.json"
                ),
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_with_pressure.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "pods_at_risk" in data
        assert "pods" in data

    def test_warn_only_filter(self, capsys):
        """Warn-only filter shows only at-risk pods."""
        from scripts.k8s.pod_eviction_risk_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_eviction_risk.json"
                ),
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_with_pressure.json"
                ),
            },
        )
        output = Output()

        result = run(["--warn-only", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # All returned pods should be at risk
        for pod in data["pods"]:
            assert pod["risk_level"] not in ("NONE", "LOW")

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.pod_eviction_risk_analyzer import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_determine_qos_guaranteed(self):
        """Guaranteed QoS is correctly determined."""
        from scripts.k8s.pod_eviction_risk_analyzer import determine_qos_class

        pod = {
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "resources": {
                            "limits": {"memory": "512Mi", "cpu": "500m"},
                            "requests": {"memory": "512Mi", "cpu": "500m"},
                        },
                    }
                ]
            }
        }

        result = determine_qos_class(pod)
        assert result == "Guaranteed"

    def test_determine_qos_besteffort(self):
        """BestEffort QoS is correctly determined."""
        from scripts.k8s.pod_eviction_risk_analyzer import determine_qos_class

        pod = {"spec": {"containers": [{"name": "app", "resources": {}}]}}

        result = determine_qos_class(pod)
        assert result == "BestEffort"

    def test_determine_qos_burstable(self):
        """Burstable QoS is correctly determined."""
        from scripts.k8s.pod_eviction_risk_analyzer import determine_qos_class

        pod = {
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "resources": {"requests": {"memory": "256Mi", "cpu": "100m"}},
                    }
                ]
            }
        }

        result = determine_qos_class(pod)
        assert result == "Burstable"
