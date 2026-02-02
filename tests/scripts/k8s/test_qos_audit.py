"""Tests for k8s qos_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestQosAudit:
    """Tests for qos_audit."""

    def test_all_guaranteed(self, capsys):
        """All Guaranteed pods return exit code 0."""
        from scripts.k8s.qos_audit import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "guaranteed", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "100m", "memory": "128Mi"},
                                },
                            }
                        ]
                    },
                    "status": {"phase": "Running", "qosClass": "Guaranteed"},
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
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_besteffort_detected(self, capsys):
        """BestEffort pods return exit code 1."""
        from scripts.k8s.qos_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_qos.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert result == 1
        assert "BestEffort" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.qos_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_qos.json"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "categories" in data
        assert "guaranteed" in data["summary"]
        assert "burstable" in data["summary"]
        assert "best_effort" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes headers."""
        from scripts.k8s.qos_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_qos.json"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out
        assert "POD" in captured.out
        assert "QOS" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy pods."""
        from scripts.k8s.qos_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_qos.json"),
            },
        )
        output = Output()

        result = run(["--format", "table", "--warn-only"], output, context)

        captured = capsys.readouterr()
        # Should only show BestEffort or critical non-Guaranteed
        if "Guaranteed" in captured.out:
            # Guaranteed should only appear in summary line, not in pod listings
            lines = [l for l in captured.out.split("\n") if "guaranteed-pod" in l.lower()]
            assert len(lines) == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.qos_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
