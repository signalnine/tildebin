"""Tests for k8s node_taint_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNodeTaintAnalyzer:
    """Tests for node_taint_analyzer."""

    def test_no_tainted_nodes(self, capsys):
        """No tainted nodes returns exit code 0."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Tainted Nodes: 0" in captured.out
        assert "Status: OK" in captured.out

    def test_tainted_nodes_detected(self, capsys):
        """Tainted nodes are detected."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_tainted.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): load_k8s_fixture(
                    "pods_simple.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        # Has tainted nodes
        captured = capsys.readouterr()
        assert "Tainted Nodes:" in captured.out
        # Should be 1 because tainted nodes exist
        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_tainted.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "tainted_nodes" in data
        assert "untainted_nodes" in data
        assert "blocking_taints" in data
        assert "pod_distribution" in data
        assert "orphaned_taints" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_tainted.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Node" in captured.out
        assert "Blocking" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag changes issues_found logic."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0

    def test_verbose_shows_details(self, capsys):
        """Verbose flag shows detailed taint info."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_tainted.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        # Verbose should show individual taint details
        assert "NoSchedule" in captured.out or "PreferNoSchedule" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.node_taint_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "tainted=" in output.summary
        assert "blocking=" in output.summary
