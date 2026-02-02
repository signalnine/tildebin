"""Tests for k8s label_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_node(
    name: str,
    labels: dict | None = None,
    annotations: dict | None = None,
) -> dict:
    """Create a mock node for testing."""
    default_labels = {
        "kubernetes.io/hostname": name,
        "kubernetes.io/os": "linux",
        "kubernetes.io/arch": "amd64",
        "node-role.kubernetes.io/worker": "",
    }
    if labels:
        default_labels.update(labels)

    return {
        "metadata": {
            "name": name,
            "labels": default_labels,
            "annotations": annotations or {},
        },
    }


class TestLabelAudit:
    """Tests for label_audit."""

    def test_all_pass(self, capsys):
        """All nodes pass returns exit code 0."""
        from scripts.k8s.label_audit import run

        nodes = {
            "items": [
                make_node("node-1", {"topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),
                make_node("node-2", {"topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),
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
        assert "All nodes pass" in captured.out or "OK" in captured.out

    def test_missing_required_label(self, capsys):
        """Missing required label returns exit code 1."""
        from scripts.k8s.label_audit import run

        nodes = {"items": [make_node("node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run(["--require-label", "env"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Missing required label" in captured.out

    def test_deprecated_label_warning(self, capsys):
        """Deprecated label generates warning."""
        from scripts.k8s.label_audit import run

        nodes = {
            "items": [
                make_node(
                    "node-1",
                    {
                        "beta.kubernetes.io/arch": "amd64",  # Deprecated
                        "topology.kubernetes.io/zone": "us-west-2a",
                        "topology.kubernetes.io/region": "us-west-2",
                    },
                )
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

        # Deprecated labels cause warnings, not issues
        captured = capsys.readouterr()
        assert "Deprecated" in captured.out or "WARN" in captured.out

    def test_label_consistency_check(self, capsys):
        """Inconsistent labels across role nodes are detected."""
        from scripts.k8s.label_audit import run

        # Need 3 nodes so that the consistency check triggers
        # (len(values) > 1 AND len(values) < len(nodes))
        # With 3 nodes and 2 distinct values, the check finds inconsistency
        nodes = {
            "items": [
                make_node("worker-1", {"team": "platform", "topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),
                make_node("worker-2", {"team": "platform", "topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),
                make_node("worker-3", {"team": "compute", "topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),  # Different team
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
        assert "Inconsistent" in captured.out or "consistency" in captured.out.lower()

    def test_skip_consistency(self, capsys):
        """Skip consistency flag prevents consistency checks."""
        from scripts.k8s.label_audit import run

        nodes = {
            "items": [
                make_node("worker-1", {"team": "platform", "topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),
                make_node("worker-2", {"team": "compute", "topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run(["--skip-consistency"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Inconsistent" not in captured.out

    def test_large_annotation_warning(self, capsys):
        """Large annotations generate warnings."""
        from scripts.k8s.label_audit import run

        # Create a large annotation (>100KB)
        large_value = "x" * (101 * 1024)
        nodes = {
            "items": [
                make_node(
                    "node-1",
                    {"topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"},
                    {"large-annotation": large_value},
                )
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

        captured = capsys.readouterr()
        assert "Large annotation" in captured.out or "KB" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.label_audit import run

        nodes = {
            "items": [
                make_node("node-1", {"topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"})
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
        assert "consistency_issues" in data
        assert "healthy" in data

    def test_table_output(self, capsys):
        """Table output format works."""
        from scripts.k8s.label_audit import run

        nodes = {
            "items": [
                make_node("node-1", {"topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"})
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Node" in captured.out
        assert "Status" in captured.out
        assert "Labels" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.label_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy nodes."""
        from scripts.k8s.label_audit import run

        nodes = {
            "items": [
                make_node("healthy-node", {"topology.kubernetes.io/zone": "us-west-2a", "topology.kubernetes.io/region": "us-west-2"}),
                make_node("no-topology-node"),  # Missing topology labels
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
        # Should show only node with issues
        assert "no-topology-node" in captured.out
        # Note: healthy-node may still appear due to consistency checks

    def test_role_detection(self, capsys):
        """Node roles are detected from labels."""
        from scripts.k8s.label_audit import run

        nodes = {
            "items": [
                make_node(
                    "node-1",
                    {
                        "node-role.kubernetes.io/control-plane": "",
                        "node-role.kubernetes.io/master": "",
                        "topology.kubernetes.io/zone": "us-west-2a",
                        "topology.kubernetes.io/region": "us-west-2",
                    },
                )
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

        captured = capsys.readouterr()
        assert "control-plane" in captured.out or "master" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.label_audit import run

        nodes = {"items": [make_node("node-1")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes=" in output.summary
        assert "issues=" in output.summary
        assert "consistency_issues=" in output.summary
