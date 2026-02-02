"""Tests for k8s configmap_secret_size script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestConfigmapSecretSize:
    """Tests for configmap_secret_size."""

    def test_no_objects(self, capsys):
        """No objects returns exit code 0."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No ConfigMaps or Secrets found" in captured.out

    def test_small_objects(self, capsys):
        """Small objects return exit code 0."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "small-cm", "namespace": "default"},
                                "data": {"key": "small value"},
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_large_configmap(self, capsys):
        """Large ConfigMap returns exit code 1."""
        from scripts.k8s.configmap_secret_size import run

        # Create a large ConfigMap (>100KB)
        large_data = "x" * 150000  # 150KB

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "large-cm", "namespace": "default"},
                                "data": {"large-file": large_data},
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "large-cm" in captured.out
        assert "WARNING" in captured.out or "warning" in captured.out

    def test_critical_size(self, capsys):
        """Critical size ConfigMap is flagged."""
        from scripts.k8s.configmap_secret_size import run

        # Create a very large ConfigMap (>500KB)
        large_data = "x" * 600000  # 600KB

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "huge-cm", "namespace": "default"},
                                "data": {"huge-file": large_data},
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "test-cm", "namespace": "default"},
                                "data": {"key": "value"},
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "thresholds" in data
        assert "summary" in data
        assert "objects" in data
        assert "total_objects" in data["summary"]
        assert "critical_count" in data["summary"]
        assert "warning_count" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "test-cm", "namespace": "default"},
                                "data": {"key": "value"},
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "TYPE" in captured.out
        assert "NAMESPACE" in captured.out
        assert "NAME" in captured.out
        assert "SIZE" in captured.out
        assert "STATUS" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_invalid_thresholds(self, capsys):
        """Invalid threshold values return exit code 2."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={},
        )
        output = Output()

        # warn-threshold >= crit-threshold is invalid
        result = run(
            ["--warn-threshold", "500KB", "--crit-threshold", "100KB"], output, context
        )

        assert result == 2

    def test_skip_system_namespaces(self, capsys):
        """Skip system namespaces flag works."""
        from scripts.k8s.configmap_secret_size import run

        large_data = "x" * 150000  # 150KB

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "large-cm", "namespace": "kube-system"},
                                "data": {"large-file": large_data},
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--skip-system"], output, context)

        # Should be OK because kube-system is skipped
        assert result == 0
        captured = capsys.readouterr()
        assert "large-cm" not in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "secrets",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "objects=" in output.summary
        assert "critical=" in output.summary
        assert "warning=" in output.summary

    def test_configmaps_only(self, capsys):
        """ConfigMaps only flag works."""
        from scripts.k8s.configmap_secret_size import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "configmaps",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "test-cm", "namespace": "default"},
                                "data": {"key": "value"},
                            }
                        ]
                    }
                ),
            },
        )
        output = Output()

        result = run(["--configmaps-only"], output, context)

        assert result == 0
        # Should not have called secrets endpoint
        secrets_cmd = ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces")
        assert secrets_cmd not in context.commands_run
