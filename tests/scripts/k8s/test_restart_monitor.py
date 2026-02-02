"""Tests for k8s restart_monitor script."""

import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_node(name: str, ready: bool = True) -> dict:
    """Create a mock node for testing."""
    now = datetime.now(timezone.utc)
    transition_time = (now - timedelta(days=5)).isoformat()

    return {
        "metadata": {"name": name},
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "reason": "KubeletReady" if ready else "KubeletNotReady",
                    "lastTransitionTime": transition_time,
                },
                {
                    "type": "MemoryPressure",
                    "status": "False",
                    "reason": "KubeletHasSufficientMemory",
                },
                {
                    "type": "DiskPressure",
                    "status": "False",
                    "reason": "KubeletHasNoDiskPressure",
                },
            ]
        },
    }


def make_pod(
    name: str,
    namespace: str = "default",
    node_name: str = "node-1",
    restart_count: int = 0,
) -> dict:
    """Create a mock pod for testing."""
    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "spec": {
            "nodeName": node_name,
        },
        "status": {
            "containerStatuses": [
                {
                    "name": "main",
                    "restartCount": restart_count,
                    "ready": True,
                    "lastState": {},
                }
            ],
        },
    }


class TestRestartMonitor:
    """Tests for restart_monitor."""

    def test_healthy_cluster(self, capsys):
        """Healthy cluster returns exit code 0."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1"), make_node("node-2")]}
        pods = {
            "items": [
                make_pod("pod-1", node_name="node-1", restart_count=0),
                make_pod("pod-2", node_name="node-2", restart_count=1),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_excessive_restarts(self, capsys):
        """Excessive pod restarts returns exit code 1."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1")]}
        pods = {
            "items": [
                make_pod("pod-1", node_name="node-1", restart_count=10),  # Excessive
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "CRITICAL" in captured.out

    def test_node_not_ready(self, capsys):
        """Node not ready returns exit code 1."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1", ready=False)]}
        pods = {"items": []}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "not ready" in captured.out.lower() or "CRITICAL" in captured.out

    def test_high_total_restarts(self, capsys):
        """High total restarts across pods returns exit code 1."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1")]}
        # Create many pods with moderate restarts
        pods = {
            "items": [
                make_pod(f"pod-{i}", node_name="node-1", restart_count=5) for i in range(10)
            ]
        }  # Total: 50 restarts

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "restarts" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1")]}
        pods = {"items": [make_pod("pod-1", node_name="node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "node-1" in data
        assert "status" in data["node-1"]
        assert "uptime_seconds" in data["node-1"]
        assert "pod_restarts" in data["node-1"]

    def test_table_output(self, capsys):
        """Table output format works."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1")]}
        pods = {"items": [make_pod("pod-1", node_name="node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Node" in captured.out
        assert "Status" in captured.out
        assert "Uptime" in captured.out

    def test_plain_output(self, capsys):
        """Plain output format works."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1")]}
        pods = {"items": [make_pod("pod-1", node_name="node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "plain"], output, context)

        captured = capsys.readouterr()
        assert "node-1" in captured.out
        assert "OK" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.restart_monitor import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy nodes."""
        from scripts.k8s.restart_monitor import run

        nodes = {
            "items": [
                make_node("healthy-node"),
                make_node("problem-node"),
            ]
        }
        pods = {
            "items": [
                make_pod("pod-1", node_name="healthy-node", restart_count=0),
                make_pod("pod-2", node_name="problem-node", restart_count=10),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        captured = capsys.readouterr()
        # Should only show problem node
        assert "problem-node" in captured.out
        # Healthy node should be filtered
        lines = captured.out.strip().split("\n")
        # Filter out header line
        data_lines = [l for l in lines if "healthy-node" in l]
        assert len(data_lines) == 0

    def test_uptime_formatting(self, capsys):
        """Uptime is formatted correctly."""
        from scripts.k8s.restart_monitor import run

        nodes = {"items": [make_node("node-1")]}
        pods = {"items": []}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        # Should show days in uptime (node was created 5 days ago in mock)
        assert "d" in captured.out or "h" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.restart_monitor import run

        nodes = {
            "items": [
                make_node("node-1"),
                make_node("node-2"),
            ]
        }
        pods = {
            "items": [
                make_pod("pod-1", node_name="node-1", restart_count=0),
                make_pod("pod-2", node_name="node-2", restart_count=10),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(pods),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes=" in output.summary
        assert "ok=" in output.summary
        assert "warning=" in output.summary
