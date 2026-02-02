"""Tests for k8s workload_ownership script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestWorkloadOwnership:
    """Tests for workload_ownership."""

    def test_managed_workloads(self, capsys):
        """Managed workloads return exit code 0."""
        from scripts.k8s.workload_ownership import run

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "web-app-abc123",
                        "namespace": "default",
                        "ownerReferences": [
                            {
                                "kind": "ReplicaSet",
                                "name": "web-app-abc12",
                                "uid": "123",
                                "controller": True,
                            }
                        ],
                    },
                }
            ]
        }

        replicaset_data = {
            "metadata": {
                "name": "web-app-abc12",
                "namespace": "default",
                "labels": {},
                "annotations": {},
                "ownerReferences": [
                    {
                        "kind": "Deployment",
                        "name": "web-app",
                        "uid": "456",
                        "controller": True,
                    }
                ],
            }
        }

        deployment_data = {
            "metadata": {
                "name": "web-app",
                "namespace": "default",
                "labels": {"app.kubernetes.io/managed-by": "helm"},
                "annotations": {},
            }
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
                ("kubectl", "get", "replicaset", "web-app-abc12", "-n", "default", "-o", "json"): json.dumps(
                    replicaset_data
                ),
                ("kubectl", "get", "deployment", "web-app", "-n", "default", "-o", "json"): json.dumps(
                    deployment_data
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_standalone_pod(self, capsys):
        """Standalone pod returns exit code 1."""
        from scripts.k8s.workload_ownership import run

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "standalone-pod",
                        "namespace": "default",
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "no_controller" in captured.out or "standalone" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.workload_ownership import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "total_pods" in data
        assert "workloads" in data
        assert "summary" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.workload_ownership import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Namespace" in captured.out
        assert "Pod" in captured.out
        assert "Generator" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.workload_ownership import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        assert ("kubectl", "get", "pods", "-o", "json", "-n", "production") in [
            tuple(cmd) for cmd in context.commands_run
        ]

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.workload_ownership import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_helm_detection(self, capsys):
        """Helm-managed workloads are detected."""
        from scripts.k8s.workload_ownership import run

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "helm-app-abc123",
                        "namespace": "default",
                        "ownerReferences": [
                            {
                                "kind": "ReplicaSet",
                                "name": "helm-app-abc12",
                                "uid": "123",
                                "controller": True,
                            }
                        ],
                    },
                }
            ]
        }

        replicaset_data = {
            "metadata": {
                "name": "helm-app-abc12",
                "namespace": "default",
                "labels": {"helm.sh/chart": "myapp-1.0.0"},
                "annotations": {},
            }
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
                ("kubectl", "get", "replicaset", "helm-app-abc12", "-n", "default", "-o", "json"): json.dumps(
                    replicaset_data
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert any(
            w["generator"]["type"] == "helm" for w in data["workloads"]
        )

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.workload_ownership import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "pods=" in output.summary
        assert "orphaned=" in output.summary
        assert "standalone=" in output.summary
