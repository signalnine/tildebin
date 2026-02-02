"""Tests for k8s emptydir_usage script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_pod_with_emptydir(
    name: str,
    namespace: str = "default",
    emptydir_name: str = "data",
    size_limit: str | None = None,
    medium: str = "",
    phase: str = "Running",
) -> dict:
    """Create a Pod with an emptyDir volume for testing."""
    emptydir_spec = {}
    if medium:
        emptydir_spec["medium"] = medium
    if size_limit:
        emptydir_spec["sizeLimit"] = size_limit

    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "containers": [
                {
                    "name": "main",
                    "volumeMounts": [{"name": emptydir_name, "mountPath": "/data"}],
                }
            ],
            "volumes": [{"name": emptydir_name, "emptyDir": emptydir_spec}],
        },
        "status": {"phase": phase},
    }


def make_pod_no_emptydir(
    name: str, namespace: str = "default", phase: str = "Running"
) -> dict:
    """Create a Pod without emptyDir volumes."""
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"containers": [{"name": "main"}], "volumes": []},
        "status": {"phase": phase},
    }


class TestEmptydirUsage:
    """Tests for emptydir_usage."""

    def test_no_issues_with_size_limits(self, capsys):
        """Pods with size limits return exit code 0."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("pod-1", size_limit="1Gi"),
                make_pod_with_emptydir("pod-2", size_limit="500Mi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_issues_with_unbounded_emptydir(self, capsys):
        """Pods with unbounded emptyDir return exit code 1."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("pod-1", size_limit=None),  # Unbounded
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "UNBOUNDED" in captured.out or "no sizeLimit" in captured.out

    def test_memory_backed_emptydir_detected(self, capsys):
        """Memory-backed emptyDir is flagged as high severity when unbounded."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("pod-1", medium="Memory", size_limit=None),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Memory" in captured.out or "tmpfs" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("pod-1", size_limit="1Gi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "cluster_summary" in data
        assert "pods" in data
        assert data["cluster_summary"]["total_pods_with_emptydir"] == 1
        assert data["cluster_summary"]["total_unbounded"] == 0

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("pod-1", size_limit="1Gi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Namespace" in captured.out
        assert "Pod" in captured.out
        assert "Volume" in captured.out
        assert "Limit" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter works correctly."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("pod-1", namespace="production", size_limit="1Gi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "production/pod-1" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy pods."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("healthy-pod", size_limit="1Gi"),
                make_pod_with_emptydir("unhealthy-pod", size_limit=None),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        # Should have issues (unbounded pod)
        assert result == 1
        captured = capsys.readouterr()
        assert "unhealthy-pod" in captured.out

    def test_excludes_system_namespaces(self, capsys):
        """System namespaces are excluded by default."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("kube-pod", namespace="kube-system", size_limit=None),
                make_pod_with_emptydir("user-pod", namespace="default", size_limit="1Gi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        # Should be 0 because kube-system is excluded
        assert result == 0
        captured = capsys.readouterr()
        assert "kube-system" not in captured.out

    def test_include_system_namespaces(self, capsys):
        """--include-system includes system namespaces."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("kube-pod", namespace="kube-system", size_limit=None),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run(["--include-system"], output, context)

        # Should have issues now
        assert result == 1
        captured = capsys.readouterr()
        assert "kube-system" in captured.out

    def test_skips_completed_pods(self, capsys):
        """Completed/Failed pods are skipped."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("completed-pod", size_limit=None, phase="Succeeded"),
                make_pod_with_emptydir("failed-pod", size_limit=None, phase="Failed"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        # No running pods with issues
        assert result == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.emptydir_usage import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_pods_without_emptydir_ignored(self, capsys):
        """Pods without emptyDir volumes are not reported."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_no_emptydir("pod-1"),
                make_pod_no_emptydir("pod-2"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No pods with emptyDir volumes found" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.emptydir_usage import run

        pods = {
            "items": [
                make_pod_with_emptydir("pod-1", size_limit="1Gi"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "pods=" in output.summary
        assert "unbounded=" in output.summary
