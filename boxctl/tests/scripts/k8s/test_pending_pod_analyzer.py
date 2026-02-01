"""Tests for pending_pod_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestPendingPodAnalyzer:
    """Tests for pending_pod_analyzer."""

    def test_no_pending_pods(self, capsys):
        """No pending pods returns exit code 0."""
        from scripts.k8s.pending_pod_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--field-selector=status.phase=Pending",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_empty.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No pending pods found" in captured.out

    def test_pending_pods_detected(self, capsys):
        """Pending pods returns exit code 1."""
        from scripts.k8s.pending_pod_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--field-selector=status.phase=Pending",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_pending.json"),
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture("nodes.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out or "production" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.pending_pod_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--field-selector=status.phase=Pending",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_pending.json"),
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture("nodes.json"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "pending_count" in data
        assert "by_category" in data
        assert "pods" in data

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.pending_pod_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--field-selector=status.phase=Pending",
                    "-n",
                    "production",
                ): load_k8s_fixture("pods_empty.json"),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.pending_pod_analyzer import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_resource_value_parsing(self):
        """Resource values are parsed correctly."""
        from scripts.k8s.pending_pod_analyzer import parse_resource_value

        # CPU
        assert parse_resource_value("100m", "cpu") == 100
        assert parse_resource_value("1", "cpu") == 1000
        assert parse_resource_value("0.5", "cpu") == 500

        # Memory
        assert parse_resource_value("1Gi", "memory") == 1024**3
        assert parse_resource_value("512Mi", "memory") == 512 * 1024**2

    def test_table_format(self, capsys):
        """Table format output is properly formatted."""
        from scripts.k8s.pending_pod_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--field-selector=status.phase=Pending",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_pending.json"),
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture("nodes.json"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out
        assert "POD NAME" in captured.out
        assert "CATEGORY" in captured.out
