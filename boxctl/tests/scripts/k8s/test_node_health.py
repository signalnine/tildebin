"""Tests for k8s node_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext, load_fixture


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNodeHealth:
    """Tests for node_health."""

    def test_all_nodes_healthy(self, capsys):
        """All healthy nodes returns exit code 0."""
        from scripts.k8s.node_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "READY" in captured.out
        assert "Summary:" in captured.out

    def test_unhealthy_nodes(self, capsys):
        """Unhealthy nodes returns exit code 1."""
        from scripts.k8s.node_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_unhealthy.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "NOT READY" in captured.out or "WARNING" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.node_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert isinstance(data, list)
        assert len(data) > 0
        assert "name" in data[0]
        assert "ready" in data[0]
        assert "allocatable" in data[0]

    def test_warn_only_hides_healthy(self, capsys):
        """Warn-only flag hides healthy nodes."""
        from scripts.k8s.node_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should only have summary, no individual node output
        assert "Summary:" in captured.out

    def test_warn_only_shows_unhealthy(self, capsys):
        """Warn-only flag shows unhealthy nodes."""
        from scripts.k8s.node_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_unhealthy.json"
                ),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Node:" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.node_health import run

        context = MockContext(
            tools_available=[],  # No kubectl
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_output(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.node_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_healthy.json"
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes=" in output.summary
        assert "healthy=" in output.summary
