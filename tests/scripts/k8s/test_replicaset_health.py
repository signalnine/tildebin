"""Tests for k8s replicaset_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestReplicasetHealth:
    """Tests for replicaset_health."""

    def test_all_healthy(self, capsys):
        """All healthy ReplicaSets return exit code 0."""
        from scripts.k8s.replicaset_health import run

        replicasets = {
            "items": [
                {
                    "metadata": {
                        "name": "webapp-abc123",
                        "namespace": "default",
                        "labels": {"pod-template-hash": "abc123"},
                        "ownerReferences": [{"kind": "Deployment", "name": "webapp"}],
                        "creationTimestamp": "2024-01-15T10:00:00Z",
                    },
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 3,
                        "availableReplicas": 3,
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "replicasets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(replicasets),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_unavailable_replicas(self, capsys):
        """Unavailable replicas return exit code 1."""
        from scripts.k8s.replicaset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "replicasets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("replicasets.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert result == 1
        assert "not ready" in captured.out.lower() or "ISSUE" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.replicaset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "replicasets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("replicasets.json"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "replicasets" in data
        assert "total" in data["summary"]
        assert "with_issues" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes headers."""
        from scripts.k8s.replicaset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "replicasets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("replicasets.json"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Namespace" in captured.out
        assert "Name" in captured.out
        assert "Ready" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy ReplicaSets."""
        from scripts.k8s.replicaset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "replicasets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("replicasets.json"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        captured = capsys.readouterr()
        # Should only show unhealthy
        lines = [l for l in captured.out.split("\n") if "webapp" in l.lower()]
        # webapp is healthy (3/3), should not appear
        assert len(lines) == 0 or "UNHEALTHY" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.replicaset_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
