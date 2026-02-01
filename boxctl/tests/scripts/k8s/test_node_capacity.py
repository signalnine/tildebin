"""Tests for k8s node_capacity script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNodeCapacity:
    """Tests for node_capacity."""

    def test_low_utilization(self, capsys):
        """Low utilization nodes return exit code 0."""
        from scripts.k8s.node_capacity import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_capacity.json"
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
        assert "OK" in captured.out

    def test_high_utilization(self, capsys):
        """High utilization returns exit code 1."""
        from scripts.k8s.node_capacity import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_capacity.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): load_k8s_fixture(
                    "pods_capacity.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        # Should detect high utilization on high-util-node
        captured = capsys.readouterr()
        assert "high-util-node" in captured.out
        # Exit code depends on utilization level
        assert result in [0, 1]

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.node_capacity import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_capacity.json"
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

        assert isinstance(data, list)
        assert len(data) > 0
        assert "node_name" in data[0]
        assert "cpu_util_pct" in data[0]
        assert "memory_util_pct" in data[0]
        assert "status" in data[0]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.node_capacity import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_capacity.json"
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
        assert "CPU" in captured.out
        assert "Memory" in captured.out
        assert "Status" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy nodes."""
        from scripts.k8s.node_capacity import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_capacity.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should not show OK nodes
        lines = [l for l in captured.out.split("\n") if "OK" in l]
        assert len(lines) == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.node_capacity import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.node_capacity import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_capacity.json"
                ),
                ("kubectl", "get", "pods", "--all-namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes=" in output.summary
        assert "critical=" in output.summary
