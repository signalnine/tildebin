"""Tests for k8s kubelet_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def make_node(name: str, ready: bool = True, version: str = "v1.28.0",
              memory_pressure: bool = False, disk_pressure: bool = False,
              cordoned: bool = False, heartbeat_age: int = 10) -> dict:
    """Create a mock node for testing."""
    from datetime import datetime, timezone, timedelta

    heartbeat_time = (datetime.now(timezone.utc) - timedelta(seconds=heartbeat_age)).isoformat()

    return {
        "metadata": {
            "name": name,
            "labels": {"kubernetes.io/hostname": name},
        },
        "spec": {
            "unschedulable": cordoned,
            "taints": [],
        },
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "reason": "KubeletReady" if ready else "KubeletNotReady",
                    "message": "kubelet is posting ready status" if ready else "kubelet not ready",
                    "lastHeartbeatTime": heartbeat_time,
                    "lastTransitionTime": heartbeat_time,
                },
                {
                    "type": "MemoryPressure",
                    "status": "True" if memory_pressure else "False",
                    "reason": "KubeletHasMemoryPressure" if memory_pressure else "KubeletHasNoMemoryPressure",
                    "message": "",
                },
                {
                    "type": "DiskPressure",
                    "status": "True" if disk_pressure else "False",
                    "reason": "KubeletHasDiskPressure" if disk_pressure else "KubeletHasNoDiskPressure",
                    "message": "",
                },
                {
                    "type": "PIDPressure",
                    "status": "False",
                    "reason": "KubeletHasSufficientPID",
                    "message": "",
                },
            ],
            "nodeInfo": {
                "kubeletVersion": version,
                "containerRuntimeVersion": "containerd://1.7.0",
                "osImage": "Ubuntu 22.04",
                "kernelVersion": "5.15.0-generic",
            },
        },
    }


class TestKubeletHealth:
    """Tests for kubelet_health."""

    def test_all_healthy(self, capsys):
        """All healthy kubelets return exit code 0."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("node-1"),
                make_node("node-2"),
                make_node("node-3"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "3/3 healthy" in captured.out

    def test_node_not_ready(self, capsys):
        """Node not ready returns exit code 1."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("node-1"),
                make_node("node-2", ready=False),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "UNHEALTHY" in captured.out
        assert "node-2" in captured.out

    def test_memory_pressure(self, capsys):
        """Node with memory pressure returns exit code 1."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("node-1", memory_pressure=True),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "MemoryPressure" in captured.out

    def test_version_mismatch(self, capsys):
        """Mixed kubelet versions returns exit code 1."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("node-1", version="v1.28.0"),
                make_node("node-2", version="v1.27.0"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Mixed" in captured.out or "Inconsistent" in captured.out

    def test_cordoned_node(self, capsys):
        """Cordoned node shows as issue."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("node-1", cordoned=True),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "cordoned" in captured.out.lower() or "CORDONED" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("node-1"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "nodes" in data
        assert data["summary"]["total"] == 1
        assert data["summary"]["healthy"] == 1

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy nodes."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("healthy-node"),
                make_node("unhealthy-node", ready=False),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        captured = capsys.readouterr()
        assert "healthy-node" not in captured.out or "unhealthy-node" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.kubelet_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_label_selector(self, capsys):
        """Label selector is passed to kubectl."""
        from scripts.k8s.kubelet_health import run

        nodes = {"items": [make_node("worker-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json", "-l", "node-role=worker"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run(["--label", "node-role=worker"], output, context)

        assert result == 0

    def test_specific_node(self, capsys):
        """Specific node query works."""
        from scripts.k8s.kubelet_health import run

        # Single node response (not a list)
        node = make_node("worker-1")
        node["kind"] = "Node"

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json", "worker-1"): json.dumps(node),
            },
        )
        output = Output()

        result = run(["--node", "worker-1"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "worker-1" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.kubelet_health import run

        nodes = {
            "items": [
                make_node("node-1"),
                make_node("node-2", ready=False),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes=2" in output.summary
        assert "healthy=1" in output.summary
        assert "unhealthy=1" in output.summary
