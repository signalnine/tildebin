"""Tests for k8s priority_class script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestPriorityClass:
    """Tests for priority_class."""

    def test_no_issues(self, capsys):
        """All pods with priority return exit code 0."""
        from scripts.k8s.priority_class import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "pod-1", "namespace": "default"},
                    "spec": {"priorityClassName": "high-priority", "priority": 1000000},
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "priorityclasses", "-o", "json"): load_k8s_fixture(
                    "priorityclasses.json"
                ),
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

    def test_pods_without_priority(self, capsys):
        """Pods without priority return exit code 0 with INFO."""
        from scripts.k8s.priority_class import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "priorityclasses", "-o", "json"): load_k8s_fixture(
                    "priorityclasses.json"
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_priority.json"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        # Should detect pods without priority (INFO level)
        assert "no explicit PriorityClass" in captured.out or "INFO" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.priority_class import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "priorityclasses", "-o", "json"): load_k8s_fixture(
                    "priorityclasses.json"
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_priority.json"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "analysis" in data
        assert "issues" in data
        assert "priority_classes" in data["analysis"]

    def test_table_output(self, capsys):
        """Table output includes headers."""
        from scripts.k8s.priority_class import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "priorityclasses", "-o", "json"): load_k8s_fixture(
                    "priorityclasses.json"
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): load_k8s_fixture("pods_priority.json"),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "PriorityClass" in captured.out
        assert "Value" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.priority_class import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
