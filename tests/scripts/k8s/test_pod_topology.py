"""Tests for k8s pod_topology script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestPodTopology:
    """Tests for pod_topology."""

    def test_no_issues_with_spread(self, capsys):
        """Workloads with topology spread return exit code 0."""
        from scripts.k8s.pod_topology import run

        # Create well-distributed pods
        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "pod-1",
                        "namespace": "default",
                        "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-1"}],
                    },
                    "spec": {"nodeName": "node-1"},
                },
                {
                    "metadata": {
                        "name": "pod-2",
                        "namespace": "default",
                        "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-1"}],
                    },
                    "spec": {"nodeName": "node-2"},
                },
            ]
        }

        nodes = {
            "items": [
                {
                    "metadata": {
                        "name": "node-1",
                        "labels": {"topology.kubernetes.io/zone": "zone-a"},
                    }
                },
                {
                    "metadata": {
                        "name": "node-2",
                        "labels": {"topology.kubernetes.io/zone": "zone-b"},
                    }
                },
            ]
        }

        deployments = {
            "items": [
                {
                    "metadata": {"name": "app", "namespace": "default"},
                    "spec": {
                        "replicas": 2,
                        "template": {
                            "spec": {
                                "topologySpreadConstraints": [
                                    {"topologyKey": "topology.kubernetes.io/zone"}
                                ]
                            }
                        },
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
                (
                    "kubectl",
                    "get",
                    "deployments",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(deployments),
                (
                    "kubectl",
                    "get",
                    "statefulsets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        # Has topology constraints, should be OK
        assert result == 0

    def test_single_node_concentration(self, capsys):
        """Pods concentrated on single node return exit code 1."""
        from scripts.k8s.pod_topology import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_topology.json"
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_topology.json"),
                (
                    "kubectl",
                    "get",
                    "deployments",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("deployments_topology.json"),
                (
                    "kubectl",
                    "get",
                    "statefulsets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("statefulsets_topology.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        # Should detect single node concentration
        assert result == 1
        assert "single node" in captured.out.lower() or "WARNING" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.pod_topology import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_topology.json"
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_topology.json"),
                (
                    "kubectl",
                    "get",
                    "deployments",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("deployments_topology.json"),
                (
                    "kubectl",
                    "get",
                    "statefulsets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("statefulsets_topology.json"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "workloads" in data
        assert "distribution_issues" in data

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.pod_topology import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
