"""Tests for k8s node_pressure script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestNodePressure:
    """Tests for node_pressure."""

    def test_no_pressure(self, capsys):
        """No pressure conditions returns exit code 0."""
        from scripts.k8s.node_pressure import run

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
        assert "[OK]" in captured.out
        assert "no pressure detected" in captured.out

    def test_pressure_detected(self, capsys):
        """Pressure conditions returns exit code 1."""
        from scripts.k8s.node_pressure import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_pressure.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[PRESSURE]" in captured.out
        assert "MemoryPressure" in captured.out or "DiskPressure" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.node_pressure import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_pressure.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "nodes" in data
        assert "summary" in data
        assert "nodes_with_pressure" in data["summary"]
        assert len(data["nodes"]) > 0
        assert "issues" in data["nodes"][0]

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy nodes."""
        from scripts.k8s.node_pressure import run

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
        # Should have summary but no individual nodes
        assert "Summary:" in captured.out

    def test_reserved_warn_threshold(self, capsys):
        """Custom reserved-warn threshold is respected."""
        from scripts.k8s.node_pressure import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): load_k8s_fixture(
                    "nodes_pressure.json"
                ),
            },
        )
        output = Output()

        # With very high threshold, should not warn about reservations
        result = run(["--reserved-warn", "99"], output, context)

        captured = capsys.readouterr()
        # Still should detect pressure issues
        assert "[PRESSURE]" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.node_pressure import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.node_pressure import run

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
        assert "pressure=" in output.summary
