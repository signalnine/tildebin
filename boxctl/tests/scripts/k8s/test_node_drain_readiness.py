"""Tests for k8s node_drain_readiness script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNodeDrainReadiness:
    """Tests for node_drain_readiness."""

    def test_node_with_evictable_pods(self, capsys):
        """Node with only evictable pods returns exit code 0."""
        from scripts.k8s.node_drain_readiness import run

        # Create pods without issues
        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "simple-pod",
                        "namespace": "default",
                        "labels": {},
                    },
                    "spec": {"nodeName": "test-node", "volumes": []},
                    "status": {"phase": "Running"},
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-A",
                    "-o",
                    "json",
                    "--field-selector",
                    "spec.nodeName=test-node",
                ): json.dumps(pods_data),
                ("kubectl", "get", "pdb", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["test-node"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "EVICTABLE" in captured.out or "Yes" in captured.out

    def test_node_with_blocking_pods(self, capsys):
        """Node with blocking pods returns exit code 1."""
        from scripts.k8s.node_drain_readiness import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-A",
                    "-o",
                    "json",
                    "--field-selector",
                    "spec.nodeName=drain-node-1",
                ): load_k8s_fixture("pods_for_drain.json"),
                ("kubectl", "get", "pdb", "-A", "-o", "json"): load_k8s_fixture(
                    "pdbs.json"
                ),
            },
        )
        output = Output()

        result = run(["drain-node-1"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        # Should detect emptyDir, DaemonSet, StatefulSet, or critical pod
        assert any(
            x in captured.out
            for x in ["emptyDir", "DaemonSet", "StatefulSet", "critical", "No"]
        )

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.node_drain_readiness import run

        pods_data = {"items": []}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-A",
                    "-o",
                    "json",
                    "--field-selector",
                    "spec.nodeName=test-node",
                ): json.dumps(pods_data),
                ("kubectl", "get", "pdb", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["test-node", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "node" in data
        assert "pod_count" in data
        assert "eviction_warnings" in data
        assert "pods" in data

    def test_check_all_nodes(self, capsys):
        """Check-all action checks all nodes."""
        from scripts.k8s.node_drain_readiness import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-A",
                    "-o",
                    "json",
                    "--field-selector",
                    "spec.nodeName=node-1",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-A",
                    "-o",
                    "json",
                    "--field-selector",
                    "spec.nodeName=node-2",
                ): json.dumps({"items": []}),
                ("kubectl", "get", "pdb", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--action", "check-all"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "node-1" in captured.out
        assert "node-2" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters evictable pods."""
        from scripts.k8s.node_drain_readiness import run

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "simple-pod",
                        "namespace": "default",
                        "labels": {},
                    },
                    "spec": {"nodeName": "test-node", "volumes": []},
                    "status": {"phase": "Running"},
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-A",
                    "-o",
                    "json",
                    "--field-selector",
                    "spec.nodeName=test-node",
                ): json.dumps(pods_data),
                ("kubectl", "get", "pdb", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["test-node", "--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should not show the simple pod that is evictable
        assert "simple-pod" not in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.node_drain_readiness import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run(["test-node"], output, context)

        assert result == 2

    def test_missing_node_argument(self, capsys):
        """Missing node argument returns exit code 2."""
        from scripts.k8s.node_drain_readiness import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
