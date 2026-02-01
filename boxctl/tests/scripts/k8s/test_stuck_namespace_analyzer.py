"""Tests for stuck_namespace_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def namespaces_with_stuck(fixtures_dir):
    """Load namespaces including stuck ones."""
    return (fixtures_dir / "k8s" / "namespaces_with_stuck.json").read_text()


@pytest.fixture
def namespace_stuck_detail(fixtures_dir):
    """Load detailed stuck namespace."""
    return (fixtures_dir / "k8s" / "namespace_stuck_detail.json").read_text()


@pytest.fixture
def namespaces_healthy(fixtures_dir):
    """Load healthy namespaces (no stuck)."""
    return (fixtures_dir / "k8s" / "namespaces.json").read_text()


@pytest.fixture
def empty_list():
    """Empty Kubernetes list."""
    return json.dumps({"apiVersion": "v1", "kind": "NamespaceList", "items": []})


class TestStuckNamespaceAnalyzer:
    """Tests for stuck_namespace_analyzer script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import stuck_namespace_analyzer

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = stuck_namespace_analyzer.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_stuck_namespaces(self, mock_context, namespaces_healthy):
        """Returns 0 when no stuck namespaces found."""
        from scripts.k8s import stuck_namespace_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_healthy,
            }
        )
        output = Output()

        exit_code = stuck_namespace_analyzer.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_stuck"] == 0

    def test_detects_stuck_namespaces(self, mock_context, namespaces_with_stuck, namespace_stuck_detail):
        """Detects namespaces in Terminating state."""
        from scripts.k8s import stuck_namespace_analyzer

        # Create detail responses for both stuck namespaces
        another_stuck = json.dumps({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "another-stuck",
                "deletionTimestamp": "2024-01-16T14:00:00Z"
            },
            "status": {"phase": "Terminating"}
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_with_stuck,
                ("kubectl", "get", "namespace", "stuck-namespace", "-o", "json"): namespace_stuck_detail,
                ("kubectl", "get", "namespace", "another-stuck", "-o", "json"): another_stuck,
            }
        )
        output = Output()

        exit_code = stuck_namespace_analyzer.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["total_stuck"] == 2
        assert len(output.data["stuck_namespaces"]) == 2

    def test_analyzes_finalizers(self, mock_context, namespaces_with_stuck, namespace_stuck_detail):
        """Analyzes namespace finalizers."""
        from scripts.k8s import stuck_namespace_analyzer

        another_stuck = json.dumps({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "another-stuck", "deletionTimestamp": "2024-01-16T14:00:00Z"},
            "status": {"phase": "Terminating"}
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_with_stuck,
                ("kubectl", "get", "namespace", "stuck-namespace", "-o", "json"): namespace_stuck_detail,
                ("kubectl", "get", "namespace", "another-stuck", "-o", "json"): another_stuck,
            }
        )
        output = Output()

        exit_code = stuck_namespace_analyzer.run([], output, ctx)

        stuck_ns = next(
            (n for n in output.data["stuck_namespaces"] if n["namespace"] == "stuck-namespace"),
            None
        )
        assert stuck_ns is not None
        assert len(stuck_ns["finalizers"]) > 0
        assert "kubernetes" in stuck_ns["finalizers"]

    def test_detects_conditions(self, mock_context, namespaces_with_stuck, namespace_stuck_detail):
        """Detects namespace deletion conditions."""
        from scripts.k8s import stuck_namespace_analyzer

        another_stuck = json.dumps({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "another-stuck", "deletionTimestamp": "2024-01-16T14:00:00Z"},
            "status": {"phase": "Terminating"}
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_with_stuck,
                ("kubectl", "get", "namespace", "stuck-namespace", "-o", "json"): namespace_stuck_detail,
                ("kubectl", "get", "namespace", "another-stuck", "-o", "json"): another_stuck,
            }
        )
        output = Output()

        exit_code = stuck_namespace_analyzer.run([], output, ctx)

        stuck_ns = next(
            (n for n in output.data["stuck_namespaces"] if n["namespace"] == "stuck-namespace"),
            None
        )
        assert stuck_ns is not None
        issue_types = [i["type"] for i in stuck_ns["issues"]]
        assert "deletion_content_failure" in issue_types or "content_remaining" in issue_types

    def test_generates_remediation(self, mock_context, namespaces_with_stuck, namespace_stuck_detail):
        """Generates remediation commands."""
        from scripts.k8s import stuck_namespace_analyzer

        another_stuck = json.dumps({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "another-stuck", "deletionTimestamp": "2024-01-16T14:00:00Z"},
            "status": {"phase": "Terminating"}
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_with_stuck,
                ("kubectl", "get", "namespace", "stuck-namespace", "-o", "json"): namespace_stuck_detail,
                ("kubectl", "get", "namespace", "another-stuck", "-o", "json"): another_stuck,
            }
        )
        output = Output()

        exit_code = stuck_namespace_analyzer.run([], output, ctx)

        stuck_ns = next(
            (n for n in output.data["stuck_namespaces"] if n["namespace"] == "stuck-namespace"),
            None
        )
        assert stuck_ns is not None
        assert "remediation" in stuck_ns
        assert len(stuck_ns["remediation"]) > 0

    def test_specific_namespace_not_stuck(self, mock_context):
        """Returns 0 when specific namespace is not stuck."""
        from scripts.k8s import stuck_namespace_analyzer

        active_ns = json.dumps({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "active-ns"},
            "status": {"phase": "Active"}
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespace", "active-ns", "-o", "json"): active_ns,
            }
        )
        output = Output()

        exit_code = stuck_namespace_analyzer.run(["--namespace", "active-ns"], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_stuck"] == 0

    def test_specific_namespace_not_found(self, mock_context):
        """Returns 2 when specific namespace not found."""
        from scripts.k8s import stuck_namespace_analyzer

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                # Simulate not found by returning empty/error
            }
        )

        # Mock a failed command
        class FailedContext:
            def check_tool(self, name):
                return True
            def run(self, cmd, check=True):
                class Result:
                    stdout = ""
                    returncode = 1
                return Result()

        output = Output()
        exit_code = stuck_namespace_analyzer.run(
            ["--namespace", "nonexistent"],
            output,
            FailedContext()
        )

        assert exit_code == 2
