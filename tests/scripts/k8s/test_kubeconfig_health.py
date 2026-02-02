"""Tests for k8s kubeconfig_health script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestKubeconfigHealth:
    """Tests for kubeconfig_health."""

    def get_valid_kubeconfig(self) -> dict:
        """Generate a valid kubeconfig JSON."""
        return {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "test-context",
            "contexts": [
                {
                    "name": "test-context",
                    "context": {
                        "cluster": "test-cluster",
                        "user": "test-user",
                        "namespace": "default",
                    },
                }
            ],
            "clusters": [
                {
                    "name": "test-cluster",
                    "cluster": {"server": "https://localhost:6443"},
                }
            ],
            "users": [
                {
                    "name": "test-user",
                    "user": {"token": "test-token"},
                }
            ],
        }

    def test_no_connectivity_check(self, capsys):
        """Skip connectivity returns 0 for valid config."""
        from scripts.k8s.kubeconfig_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "config",
                    "view",
                    "--raw",
                    "-o",
                    "json",
                    "--kubeconfig",
                    "/home/user/.kube/config",
                ): json.dumps(self.get_valid_kubeconfig()),
            },
            file_contents={"/home/user/.kube/config": "exists"},
            env={"HOME": "/home/user"},
        )
        output = Output()

        result = run(
            ["--no-connectivity", "--kubeconfig", "/home/user/.kube/config"],
            output,
            context,
        )

        assert result == 0

    def test_file_not_found(self, capsys):
        """Missing kubeconfig file returns exit code 1."""
        from scripts.k8s.kubeconfig_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={},
            file_contents={},
        )
        output = Output()

        result = run(
            ["--kubeconfig", "/nonexistent/kubeconfig", "--no-connectivity"],
            output,
            context,
        )

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.kubeconfig_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "config",
                    "view",
                    "--raw",
                    "-o",
                    "json",
                    "--kubeconfig",
                    "/home/user/.kube/config",
                ): json.dumps(self.get_valid_kubeconfig()),
            },
            file_contents={"/home/user/.kube/config": "exists"},
        )
        output = Output()

        result = run(
            [
                "--format",
                "json",
                "--no-connectivity",
                "--kubeconfig",
                "/home/user/.kube/config",
            ],
            output,
            context,
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "kubeconfigs" in data
        assert "issues" in data
        assert "warnings" in data
        assert "healthy" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.kubeconfig_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "config",
                    "view",
                    "--raw",
                    "-o",
                    "json",
                    "--kubeconfig",
                    "/home/user/.kube/config",
                ): json.dumps(self.get_valid_kubeconfig()),
            },
            file_contents={"/home/user/.kube/config": "exists"},
        )
        output = Output()

        result = run(
            [
                "--format",
                "table",
                "--no-connectivity",
                "--kubeconfig",
                "/home/user/.kube/config",
            ],
            output,
            context,
        )

        captured = capsys.readouterr()
        assert "Context" in captured.out
        assert "Server" in captured.out
        assert "Kubeconfig Health Check" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.kubeconfig_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_empty_contexts(self, capsys):
        """Empty contexts in kubeconfig reports issue."""
        from scripts.k8s.kubeconfig_health import run

        empty_config = {
            "apiVersion": "v1",
            "kind": "Config",
            "contexts": [],
            "clusters": [],
            "users": [],
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "config",
                    "view",
                    "--raw",
                    "-o",
                    "json",
                    "--kubeconfig",
                    "/home/user/.kube/config",
                ): json.dumps(empty_config),
            },
            file_contents={"/home/user/.kube/config": "exists"},
        )
        output = Output()

        result = run(
            ["--no-connectivity", "--kubeconfig", "/home/user/.kube/config"],
            output,
            context,
        )

        assert result == 1
        captured = capsys.readouterr()
        assert "No contexts" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.kubeconfig_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "config",
                    "view",
                    "--raw",
                    "-o",
                    "json",
                    "--kubeconfig",
                    "/home/user/.kube/config",
                ): json.dumps(self.get_valid_kubeconfig()),
            },
            file_contents={"/home/user/.kube/config": "exists"},
        )
        output = Output()

        run(
            ["--no-connectivity", "--kubeconfig", "/home/user/.kube/config"],
            output,
            context,
        )

        assert "kubeconfigs=" in output.summary
        assert "issues=" in output.summary
        assert "warnings=" in output.summary

    def test_missing_cluster_reference(self, capsys):
        """Missing cluster reference reports issue."""
        from scripts.k8s.kubeconfig_health import run

        bad_config = {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "test-context",
            "contexts": [
                {
                    "name": "test-context",
                    "context": {
                        "cluster": "nonexistent-cluster",
                        "user": "test-user",
                    },
                }
            ],
            "clusters": [],
            "users": [{"name": "test-user", "user": {"token": "test"}}],
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "config",
                    "view",
                    "--raw",
                    "-o",
                    "json",
                    "--kubeconfig",
                    "/home/user/.kube/config",
                ): json.dumps(bad_config),
            },
            file_contents={"/home/user/.kube/config": "exists"},
        )
        output = Output()

        result = run(
            ["--no-connectivity", "--kubeconfig", "/home/user/.kube/config"],
            output,
            context,
        )

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()
