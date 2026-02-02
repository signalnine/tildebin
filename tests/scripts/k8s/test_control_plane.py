"""Tests for k8s control_plane script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestControlPlane:
    """Tests for control_plane."""

    def test_healthy_control_plane(self, capsys):
        """Healthy control plane returns exit code 0."""
        from scripts.k8s.control_plane import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                # API server health
                ("kubectl", "get", "--raw", "/healthz"): "ok",
                ("kubectl", "get", "--raw", "/readyz"): "ok",
                ("kubectl", "get", "--raw", "/livez"): "ok",
                # Control plane pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "tier=control-plane",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "kube-apiserver-master"},
                                "status": {
                                    "phase": "Running",
                                    "containerStatuses": [
                                        {"name": "kube-apiserver", "ready": True, "restartCount": 0}
                                    ],
                                },
                            }
                        ]
                    }
                ),
                # etcd pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "component=etcd",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "etcd-master"},
                                "status": {
                                    "phase": "Running",
                                    "containerStatuses": [
                                        {"name": "etcd", "ready": True, "restartCount": 0}
                                    ],
                                },
                            }
                        ]
                    }
                ),
                # Leases
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-controller-manager",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "spec": {
                            "holderIdentity": "master_abc",
                            "renewTime": "2024-01-01T12:00:00Z",
                        }
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-scheduler",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "spec": {
                            "holderIdentity": "master_xyz",
                            "renewTime": "2024-01-01T12:00:00Z",
                        }
                    }
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out

    def test_api_server_unavailable(self, capsys):
        """Unavailable API server returns exit code 1."""
        from scripts.k8s.control_plane import run

        # Create a mock that returns failure for health endpoints
        class FailingMockContext(MockContext):
            def run(self, cmd, **kwargs):
                import subprocess

                if "--raw" in cmd and "/healthz" in cmd:
                    return subprocess.CompletedProcess(cmd, 1, "", "connection refused")
                if "--raw" in cmd and "/readyz" in cmd:
                    return subprocess.CompletedProcess(cmd, 1, "", "connection refused")
                if "--raw" in cmd and "/livez" in cmd:
                    return subprocess.CompletedProcess(cmd, 1, "", "connection refused")
                return super().run(cmd, **kwargs)

        context = FailingMockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "tier=control-plane",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "component=etcd",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-controller-manager",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-scheduler",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "unhealthy" in captured.out.lower() or "unavailable" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.control_plane import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "--raw", "/healthz"): "ok",
                ("kubectl", "get", "--raw", "/readyz"): "ok",
                ("kubectl", "get", "--raw", "/livez"): "ok",
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "tier=control-plane",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "component=etcd",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-controller-manager",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-scheduler",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "api_server" in data
        assert "components" in data
        assert "issues" in data
        assert "warnings" in data
        assert "healthy" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.control_plane import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "--raw", "/healthz"): "ok",
                ("kubectl", "get", "--raw", "/readyz"): "ok",
                ("kubectl", "get", "--raw", "/livez"): "ok",
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "tier=control-plane",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "component=etcd",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-controller-manager",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-scheduler",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Component" in captured.out
        assert "Status" in captured.out
        assert "API Server" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.control_plane import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.control_plane import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "--raw", "/healthz"): "ok",
                ("kubectl", "get", "--raw", "/readyz"): "ok",
                ("kubectl", "get", "--raw", "/livez"): "ok",
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "tier=control-plane",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "component=etcd",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-controller-manager",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-scheduler",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
            },
        )
        output = Output()

        run([], output, context)

        assert "issues=" in output.summary
        assert "warnings=" in output.summary

    def test_etcd_quorum_at_risk(self, capsys):
        """etcd quorum at risk triggers issue."""
        from scripts.k8s.control_plane import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "--raw", "/healthz"): "ok",
                ("kubectl", "get", "--raw", "/readyz"): "ok",
                ("kubectl", "get", "--raw", "/livez"): "ok",
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "tier=control-plane",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                # 3 etcd pods, only 1 healthy (quorum at risk)
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "component=etcd",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "etcd-1"},
                                "status": {
                                    "phase": "Running",
                                    "containerStatuses": [
                                        {"name": "etcd", "ready": True, "restartCount": 0}
                                    ],
                                },
                            },
                            {
                                "metadata": {"name": "etcd-2"},
                                "status": {
                                    "phase": "Failed",
                                    "containerStatuses": [
                                        {"name": "etcd", "ready": False, "restartCount": 0}
                                    ],
                                },
                            },
                            {
                                "metadata": {"name": "etcd-3"},
                                "status": {
                                    "phase": "Failed",
                                    "containerStatuses": [
                                        {"name": "etcd", "ready": False, "restartCount": 0}
                                    ],
                                },
                            },
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-controller-manager",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
                (
                    "kubectl",
                    "get",
                    "lease",
                    "kube-scheduler",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps({"spec": {}}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "quorum" in captured.out.lower() or "etcd" in captured.out.lower()
