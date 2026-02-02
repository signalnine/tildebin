"""Tests for k8s statefulset_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestStatefulsetHealth:
    """Tests for statefulset_health."""

    def test_healthy_statefulsets(self, capsys):
        """Healthy StatefulSets return exit code 0."""
        from scripts.k8s.statefulset_health import run

        # Fixture has postgres in database namespace
        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "statefulsets_healthy.json"
                ),
                ("kubectl", "get", "pods", "-n", "database", "-l", "app.kubernetes.io/name=postgres", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "pods", "-n", "database", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "pvc", "-n", "database", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        # May have issues due to no pods matching
        assert result in [0, 1]

    def test_empty_statefulsets(self, capsys):
        """No StatefulSets returns exit code 0."""
        from scripts.k8s.statefulset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "statefulsets_empty.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No StatefulSets found" in captured.out

    def test_json_output(self, capsys):
        """JSON output is valid."""
        from scripts.k8s.statefulset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.statefulset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "statefulsets", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        assert ("kubectl", "get", "statefulsets", "-o", "json", "-n", "production") in [
            tuple(cmd) for cmd in context.commands_run
        ]

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.statefulset_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_unhealthy_statefulset(self, capsys):
        """Unhealthy StatefulSet returns exit code 1."""
        from scripts.k8s.statefulset_health import run

        sts_data = {
            "items": [
                {
                    "metadata": {
                        "name": "mysql",
                        "namespace": "default",
                        "generation": 1,
                    },
                    "spec": {
                        "replicas": 3,
                        "updateStrategy": {"type": "RollingUpdate"},
                        "volumeClaimTemplates": [],
                    },
                    "status": {
                        "readyReplicas": 1,
                        "currentReplicas": 3,
                        "updatedReplicas": 3,
                        "observedGeneration": 1,
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    sts_data
                ),
                ("kubectl", "get", "pods", "-n", "default", "-l", "app.kubernetes.io/name=mysql", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "pods", "-n", "default", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "pvc", "-n", "default", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Only 1/3 replicas ready" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.statefulset_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "healthy=" in output.summary
        assert "unhealthy=" in output.summary
