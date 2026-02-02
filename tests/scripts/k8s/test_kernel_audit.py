"""Tests for k8s kernel_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_nodes_response(nodes: list[dict]) -> str:
    """Create a mock nodes JSON response."""
    items = []
    for node in nodes:
        items.append(
            {
                "metadata": {
                    "name": node.get("name", "node-1"),
                    "labels": node.get("labels", {}),
                },
                "status": {
                    "conditions": [
                        {
                            "type": "Ready",
                            "status": "True" if node.get("ready", True) else "False",
                        }
                    ]
                },
            }
        )
    return json.dumps({"items": items})


class TestKernelAudit:
    """Tests for kernel_audit."""

    def test_all_compliant(self, capsys):
        """All compliant nodes return exit code 0."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response(
                    [{"name": "node-1"}, {"name": "node-2"}]
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "consistent and compliant" in captured.out or "OK" in captured.out

    def test_no_nodes(self, capsys):
        """No nodes returns exit code 1."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response([{"name": "node-1"}]),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert data["summary"]["nodes_checked"] == 1

    def test_table_output(self, capsys):
        """Table output format works."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response([{"name": "node-1"}]),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Nodes:" in captured.out
        assert "Ready:" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_node_selector(self, capsys):
        """Node selector filters nodes."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response(
                    [
                        {"name": "worker-1", "labels": {"node-role.kubernetes.io/worker": ""}},
                        {"name": "master-1", "labels": {"node-role.kubernetes.io/master": ""}},
                    ]
                ),
            },
        )
        output = Output()

        result = run(["--node-selector", "node-role.kubernetes.io/worker="], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should only check worker-1
        assert "Nodes checked: 1" in captured.out or "nodes=1" in output.summary

    def test_verbose_shows_config(self, capsys):
        """Verbose flag shows kernel configuration."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response([{"name": "node-1"}]),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Kernel Parameters" in captured.out or "net.ipv4.ip_forward" in captured.out

    def test_consistency_only(self, capsys):
        """Consistency-only flag skips compliance checks."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response([{"name": "node-1"}]),
            },
        )
        output = Output()

        result = run(["--consistency-only"], output, context)

        assert result == 0

    def test_not_ready_nodes_skipped(self, capsys):
        """Not ready nodes are skipped."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response(
                    [
                        {"name": "ready-node", "ready": True},
                        {"name": "not-ready-node", "ready": False},
                    ]
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "Ready nodes: 1" in captured.out or "nodes_ready: 1" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response([{"name": "node-1"}]),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes=" in output.summary
        assert "critical=" in output.summary
        assert "warnings=" in output.summary

    def test_warn_only_filters_info(self, capsys):
        """Warn-only flag filters info messages."""
        from scripts.k8s.kernel_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): make_nodes_response([{"name": "node-1"}]),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        captured = capsys.readouterr()
        # Info messages should not appear
        assert "INFO:" not in captured.out
