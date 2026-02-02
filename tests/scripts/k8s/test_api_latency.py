"""Tests for k8s api_latency script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestApiLatency:
    """Tests for api_latency."""

    def test_healthy_latency(self, capsys):
        """All healthy operations return exit code 0."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(
                    {"items": [{"metadata": {"name": "default"}}]}
                ),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(
                    {"items": [{"metadata": {"name": "node-1"}}]}
                ),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "cluster-info"): "Kubernetes control plane is running",
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "api-resources", "--no-headers"): "pods  v1  true  Pod",
            },
        )
        output = Output()

        result = run(["--samples", "1"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "cluster-info"): "Kubernetes control plane is running",
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "api-resources", "--no-headers"): "pods  v1  true  Pod",
            },
        )
        output = Output()

        result = run(["--format", "json", "--samples", "1"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "summary" in data
        assert "operations" in data
        assert "issues" in data
        assert "warnings" in data
        assert "healthy" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "cluster-info"): "Kubernetes control plane is running",
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "api-resources", "--no-headers"): "pods  v1  true  Pod",
            },
        )
        output = Output()

        result = run(["--format", "table", "--samples", "1"], output, context)

        captured = capsys.readouterr()
        assert "Operation" in captured.out
        assert "Avg (ms)" in captured.out
        assert "Status" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_invalid_samples(self, capsys):
        """Invalid samples value returns exit code 2."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={},
        )
        output = Output()

        result = run(["--samples", "0"], output, context)

        assert result == 2

    def test_invalid_thresholds(self, capsys):
        """Invalid threshold values return exit code 2."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={},
        )
        output = Output()

        # warn-threshold >= critical-threshold is invalid
        result = run(
            ["--warn-threshold", "1000", "--critical-threshold", "500"], output, context
        )

        assert result == 2

    def test_warn_only_no_output_when_healthy(self, capsys):
        """Warn-only mode produces no output when healthy."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "cluster-info"): "Kubernetes control plane is running",
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "api-resources", "--no-headers"): "pods  v1  true  Pod",
            },
        )
        output = Output()

        result = run(["--warn-only", "--samples", "1"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should have minimal or no output in warn-only mode when healthy
        assert "ISSUE" not in captured.out
        assert "WARNING" not in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "cluster-info"): "Kubernetes control plane is running",
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "api-resources", "--no-headers"): "pods  v1  true  Pod",
            },
        )
        output = Output()

        run(["--samples", "1"], output, context)

        assert "issues=" in output.summary
        assert "warnings=" in output.summary

    def test_namespace_scoped(self, capsys):
        """Namespace flag scopes pod and event queries."""
        from scripts.k8s.api_latency import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "cluster-info"): "Kubernetes control plane is running",
                ("kubectl", "get", "events", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "api-resources", "--no-headers"): "pods  v1  true  Pod",
            },
        )
        output = Output()

        result = run(["-n", "production", "--samples", "1"], output, context)

        assert result == 0
        # Verify the namespace-scoped commands were called
        assert (
            "kubectl",
            "get",
            "pods",
            "-o",
            "json",
            "-n",
            "production",
        ) in context.commands_run
