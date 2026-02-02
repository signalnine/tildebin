"""Tests for k8s pod_scaling script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestPodScaling:
    """Tests for pod_scaling."""

    def test_healthy_deployments(self, capsys):
        """Healthy deployments return exit code 0."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 3,
                        "updatedReplicas": 3,
                        "availableReplicas": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_scaled_to_zero(self, capsys):
        """Deployment scaled to 0 returns CRITICAL."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "idle-app", "namespace": "production"},
                    "spec": {"replicas": 0},
                    "status": {
                        "replicas": 0,
                        "readyReplicas": 0
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "scaled to 0" in captured.out

    def test_not_ready_replicas(self, capsys):
        """Deployment with not-ready replicas returns WARNING."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "failing-app", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 1,
                        "updatedReplicas": 3,
                        "availableReplicas": 1
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "Not ready" in captured.out

    def test_statefulset_issues(self, capsys):
        """StatefulSet with issues returns exit code 1."""
        from scripts.k8s.pod_scaling import run

        statefulsets = {
            "items": [
                {
                    "metadata": {"name": "database", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 2
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps(statefulsets),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Not all ready" in captured.out

    def test_high_replica_count(self, capsys):
        """High replica count shows warning."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "massive-app", "namespace": "production"},
                    "spec": {"replicas": 100},
                    "status": {
                        "replicas": 100,
                        "readyReplicas": 100,
                        "updatedReplicas": 100,
                        "availableReplicas": 100
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "High replica count" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 3,
                        "updatedReplicas": 3,
                        "availableReplicas": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "summary" in data
        assert "resources" in data
        assert "total" in data["summary"]
        assert "ok" in data["summary"]
        assert "warning" in data["summary"]
        assert "critical" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 3,
                        "updatedReplicas": 3,
                        "availableReplicas": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Type" in captured.out
        assert "Namespace" in captured.out
        assert "Name" in captured.out
        assert "Status" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy resources."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "healthy-app", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 3,
                        "updatedReplicas": 3,
                        "availableReplicas": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should only show header, not the healthy app
        assert "healthy-app" not in captured.out

    def test_deployments_only(self, capsys):
        """Deployments-only flag works correctly."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 3,
                        "updatedReplicas": 3,
                        "availableReplicas": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--deployments-only"], output, context)

        assert result == 0
        # Should not call statefulsets
        commands = [tuple(cmd) for cmd in context.commands_run]
        assert not any("statefulsets" in str(cmd) for cmd in commands)

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.pod_scaling import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter uses correct kubectl args."""
        from scripts.k8s.pod_scaling import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-n", "production", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-n", "production", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-n", "production", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        # Verify correct commands were run with -n flag
        commands = [tuple(cmd) for cmd in context.commands_run]
        assert any("-n" in cmd and "production" in cmd for cmd in commands)

    def test_summary_set(self):
        """Summary is set correctly."""
        from scripts.k8s.pod_scaling import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "web-app", "namespace": "production"},
                    "spec": {"replicas": 3},
                    "status": {
                        "replicas": 3,
                        "readyReplicas": 3,
                        "updatedReplicas": 3,
                        "availableReplicas": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "hpa", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-A", "-o", "json"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-A", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "resourcequotas", "-A", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "total=" in output.summary
        assert "ok=" in output.summary
        assert "warning=" in output.summary
        assert "critical=" in output.summary
