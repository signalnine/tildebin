"""Tests for k8s daemonset_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def make_daemonset(
    name: str,
    namespace: str = "default",
    desired: int = 3,
    current: int = 3,
    ready: int = 3,
    available: int = 3,
    updated: int = 3,
    misscheduled: int = 0,
) -> dict:
    """Create a DaemonSet object for testing."""
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "updateStrategy": {"type": "RollingUpdate"},
            "template": {"spec": {}},
        },
        "status": {
            "desiredNumberScheduled": desired,
            "currentNumberScheduled": current,
            "numberReady": ready,
            "numberAvailable": available,
            "updatedNumberScheduled": updated,
            "numberMisscheduled": misscheduled,
        },
    }


def make_node(name: str, ready: bool = True, schedulable: bool = True) -> dict:
    """Create a Node object for testing."""
    return {
        "metadata": {"name": name, "labels": {}},
        "spec": {"unschedulable": not schedulable},
        "status": {
            "conditions": [
                {"type": "Ready", "status": "True" if ready else "False"}
            ]
        },
    }


def make_pod(
    name: str,
    namespace: str = "default",
    daemonset: str = "test-ds",
    node: str = "node-1",
    phase: str = "Running",
    ready: bool = True,
) -> dict:
    """Create a Pod object for testing."""
    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "ownerReferences": [{"kind": "DaemonSet", "name": daemonset}],
        },
        "spec": {"nodeName": node},
        "status": {
            "phase": phase,
            "containerStatuses": [
                {"name": "main", "ready": ready, "restartCount": 0, "state": {"running": {}}}
            ],
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        },
    }


class TestDaemonsetHealth:
    """Tests for daemonset_health."""

    def test_healthy_daemonsets(self, capsys):
        """Healthy DaemonSets return exit code 0."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1"), make_node("node-2")]}
        daemonsets = {"items": [make_daemonset("test-ds", desired=2, current=2, ready=2)]}
        pods = {
            "items": [
                make_pod("pod-1", node="node-1"),
                make_pod("pod-2", node="node-2"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    daemonsets
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_unhealthy_daemonset_missing_pods(self, capsys):
        """DaemonSet with missing pods returns exit code 1."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1"), make_node("node-2"), make_node("node-3")]}
        daemonsets = {
            "items": [make_daemonset("test-ds", desired=3, current=2, ready=2)]
        }
        pods = {
            "items": [
                make_pod("pod-1", node="node-1"),
                make_pod("pod-2", node="node-2"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    daemonsets
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[!!]" in captured.out
        assert "Only 2/3 pods scheduled" in captured.out

    def test_daemonset_not_ready(self, capsys):
        """DaemonSet with pods not ready returns exit code 1."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1"), make_node("node-2")]}
        daemonsets = {
            "items": [make_daemonset("test-ds", desired=2, current=2, ready=1)]
        }
        pods = {
            "items": [
                make_pod("pod-1", node="node-1", ready=True),
                make_pod("pod-2", node="node-2", ready=False),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    daemonsets
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Only 1/2 pods ready" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1")]}
        daemonsets = {"items": [make_daemonset("test-ds", desired=1, current=1, ready=1)]}
        pods = {"items": [make_pod("pod-1", node="node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    daemonsets
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "test-ds"
        assert "healthy" in data[0]
        assert "replicas" in data[0]
        assert "issues" in data[0]

    def test_namespace_filter(self, capsys):
        """Namespace filter works correctly."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1")]}
        daemonsets = {
            "items": [
                make_daemonset("ds-1", namespace="kube-system"),
                make_daemonset("ds-2", namespace="default"),
            ]
        }
        pods_kube_system = {"items": [make_pod("pod-1", namespace="kube-system", daemonset="ds-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "-n", "kube-system"): json.dumps(
                    {"items": [daemonsets["items"][0]]}
                ),
                ("kubectl", "get", "pods", "-n", "kube-system", "-o", "json"): json.dumps(
                    pods_kube_system
                ),
            },
        )
        output = Output()

        result = run(["-n", "kube-system"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "kube-system/ds-1" in captured.out
        assert "default/ds-2" not in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy DaemonSets."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1")]}
        daemonsets = {
            "items": [
                # All values must match for truly healthy DaemonSet
                make_daemonset("healthy-ds", desired=1, current=1, ready=1, available=1, updated=1),
                make_daemonset("unhealthy-ds", desired=1, current=1, ready=0, available=0, updated=1),
            ]
        }
        healthy_pods = {"items": [make_pod("pod-1", daemonset="healthy-ds", ready=True)]}
        unhealthy_pods = {"items": [make_pod("pod-2", daemonset="unhealthy-ds", ready=False)]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    daemonsets
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(
                    {"items": healthy_pods["items"] + unhealthy_pods["items"]}
                ),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        # Should have issues
        assert result == 1
        captured = capsys.readouterr()
        assert "unhealthy-ds" in captured.out
        # healthy-ds should be filtered out in warn-only mode
        lines = [l for l in captured.out.split("\n") if "healthy-ds" in l and "[OK]" in l]
        assert len(lines) == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.daemonset_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_misscheduled_pods(self, capsys):
        """DaemonSet with misscheduled pods reports issue."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1")]}
        daemonsets = {
            "items": [make_daemonset("test-ds", desired=1, current=1, ready=1, misscheduled=2)]
        }
        pods = {"items": [make_pod("pod-1", node="node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    daemonsets
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "2 pods running on nodes where they shouldn't" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.daemonset_health import run

        nodes = {"items": [make_node("node-1")]}
        daemonsets = {"items": [make_daemonset("test-ds", desired=1, current=1, ready=1)]}
        pods = {"items": [make_pod("pod-1", node="node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    daemonsets
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        run([], output, context)

        assert "daemonsets=" in output.summary
        assert "healthy=" in output.summary
