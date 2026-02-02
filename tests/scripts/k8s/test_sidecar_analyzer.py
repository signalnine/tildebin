"""Tests for k8s sidecar_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestSidecarAnalyzer:
    """Tests for sidecar_analyzer."""

    def test_no_sidecars(self, capsys):
        """Pods without sidecars return exit code 0."""
        from scripts.k8s.sidecar_analyzer import run

        pods_data = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {"name": "nginx", "image": "nginx:latest"}
                        ]
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "nginx", "ready": True, "restartCount": 0}
                        ],
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

        assert result == 0

    def test_istio_sidecar_detected(self, capsys):
        """Istio sidecar is properly detected."""
        from scripts.k8s.sidecar_analyzer import run

        pods_data = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {"name": "app", "image": "myapp:latest"},
                            {"name": "istio-proxy", "image": "istio/proxyv2:1.18"},
                        ]
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "app", "ready": True, "restartCount": 0},
                            {
                                "name": "istio-proxy",
                                "ready": True,
                                "restartCount": 0,
                            },
                        ],
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

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["summary"]["total_sidecars"] >= 1
        assert "istio-proxy" in data["summary"]["sidecar_types"]

    def test_sidecar_not_ready_issue(self, capsys):
        """Sidecar not ready is flagged as issue."""
        from scripts.k8s.sidecar_analyzer import run

        pods_data = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {"name": "app", "image": "myapp:latest"},
                            {"name": "istio-proxy", "image": "istio/proxyv2:1.18"},
                        ]
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "app", "ready": True, "restartCount": 0},
                            {
                                "name": "istio-proxy",
                                "ready": False,
                                "restartCount": 0,
                                "state": {"running": {}},
                            },
                        ],
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

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should have issues
        assert data["summary"]["total_issues"] > 0
        assert result == 1

    def test_high_restart_count(self, capsys):
        """High restart count is flagged as issue."""
        from scripts.k8s.sidecar_analyzer import run

        pods_data = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {"name": "app", "image": "myapp:latest"},
                            {"name": "envoy", "image": "envoyproxy/envoy:v1.27"},
                        ]
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "app", "ready": True, "restartCount": 0},
                            {
                                "name": "envoy",
                                "ready": True,
                                "restartCount": 5,
                                "state": {"running": {}},
                            },
                        ],
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

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "sidecar_high_restarts" in data["summary"]["by_issue_type"]

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.sidecar_analyzer import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json", "--warn-only"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "pods" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.sidecar_analyzer import run

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
        assert "NAMESPACE" in captured.out
        assert "POD" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.sidecar_analyzer import run

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
        from scripts.k8s.sidecar_analyzer import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.sidecar_analyzer import run

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

        assert "sidecars=" in output.summary
        assert "issues=" in output.summary
