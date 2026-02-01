"""Tests for container_restart_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext, load_fixture


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestContainerRestartAnalyzer:
    """Tests for container_restart_analyzer."""

    def test_no_restarts(self, capsys):
        """No restarts returns exit code 0."""
        from scripts.k8s.container_restart_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_no_restarts.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No container restarts detected" in captured.out

    def test_with_restarts(self, capsys):
        """Restarts detected returns exit code 1."""
        from scripts.k8s.container_restart_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_with_restarts.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Container Restart Analysis" in captured.out
        assert "OOMKilled" in captured.out or "CrashLoopBackOff" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.container_restart_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_with_restarts.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_pods" in data
        assert "total_restarts" in data
        assert "by_category" in data
        assert "flapping_containers" in data

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.container_restart_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): load_k8s_fixture(
                    "pods_with_restarts.json"
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        # Verify the namespace-specific command was called
        assert ("kubectl", "get", "pods", "-o", "json", "-n", "production") in [
            tuple(cmd) for cmd in context.commands_run
        ]

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.container_restart_analyzer import run

        context = MockContext(
            tools_available=[],  # No kubectl
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_empty_pod_list(self, capsys):
        """Empty pod list returns exit code 0."""
        from scripts.k8s.container_restart_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_empty.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_categorize_oomkill(self):
        """OOMKill is properly categorized."""
        from scripts.k8s.container_restart_analyzer import categorize_restart_reason

        result = categorize_restart_reason("OOMKilled", 137, None)
        assert result == "OOMKilled"

    def test_categorize_crashloop(self):
        """CrashLoopBackOff is properly categorized."""
        from scripts.k8s.container_restart_analyzer import categorize_restart_reason

        result = categorize_restart_reason("Error", 1, "CrashLoopBackOff")
        assert result == "CrashLoopBackOff"
