"""Tests for k8s probe_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestProbeAudit:
    """Tests for probe_audit."""

    def test_healthy_probes(self, capsys):
        """Pods with proper probes return exit code 0."""
        from scripts.k8s.probe_audit import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "healthy", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}},
                                "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                            }
                        ]
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

    def test_missing_probes(self, capsys):
        """Pods without probes return exit code 1."""
        from scripts.k8s.probe_audit import run

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
                ): load_k8s_fixture("pods_probes.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        # Should detect missing probes
        assert result == 1
        assert "missing" in captured.out.lower() or "HIGH" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.probe_audit import run

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
                ): load_k8s_fixture("pods_probes.json"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "high" in data["summary"]
        assert "medium" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes headers."""
        from scripts.k8s.probe_audit import run

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
                ): load_k8s_fixture("pods_probes.json"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Severity" in captured.out
        assert "Type" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters low severity issues."""
        from scripts.k8s.probe_audit import run

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
                ): load_k8s_fixture("pods_probes.json"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        captured = capsys.readouterr()
        # LOW severity should be filtered
        lines = captured.out.split("\n")
        low_lines = [l for l in lines if "LOW" in l]
        assert len(low_lines) == 0 or "LOW SEVERITY" not in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.probe_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
