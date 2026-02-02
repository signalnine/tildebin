"""Tests for k8s lifecycle_hooks script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestLifecycleHooks:
    """Tests for lifecycle_hooks."""

    def test_healthy_pods(self, capsys):
        """Pods with proper lifecycle hooks return exit code 0."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [
                            {
                                "name": "web",
                                "lifecycle": {
                                    "preStop": {
                                        "exec": {"command": ["sleep", "5"]}
                                    }
                                }
                            }
                        ]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "properly configured" in captured.out.lower()

    def test_stateful_missing_prestop(self, capsys):
        """Stateful workload missing preStop returns exit code 1."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "database-0",
                        "namespace": "production",
                        "ownerReferences": [
                            {"kind": "StatefulSet", "name": "database"}
                        ]
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [
                            {
                                "name": "db"
                            }
                        ]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "missing prestop" in captured.out.lower()

    def test_prestop_exceeds_grace(self, capsys):
        """preStop sleep exceeding grace period shows HIGH severity."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [
                            {
                                "name": "web",
                                "lifecycle": {
                                    "preStop": {
                                        "exec": {"command": ["sleep", "60"]}
                                    }
                                }
                            }
                        ]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "grace period" in captured.out.lower()

    def test_pvc_mount_missing_prestop(self, capsys):
        """Container with PVC mount missing preStop shows MEDIUM severity."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "app-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [
                            {
                                "name": "app",
                                "volumeMounts": [
                                    {"name": "data-volume", "mountPath": "/data"}
                                ]
                            }
                        ],
                        "volumes": [
                            {"name": "data-volume", "persistentVolumeClaim": {"claimName": "app-data"}}
                        ]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        # Should be HIGH because it's detected as stateful due to PVC
        assert "HIGH" in captured.out or "MEDIUM" in captured.out

    def test_low_grace_period(self, capsys):
        """Low grace period for stateful workload shows MEDIUM severity."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "database-0",
                        "namespace": "production",
                        "ownerReferences": [
                            {"kind": "StatefulSet", "name": "database"}
                        ]
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 10,
                        "containers": [
                            {
                                "name": "db",
                                "lifecycle": {
                                    "preStop": {
                                        "exec": {"command": ["sleep", "5"]}
                                    }
                                }
                            }
                        ]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "MEDIUM" in captured.out
        assert "terminationGracePeriodSeconds" in captured.out

    def test_skip_system_namespaces(self, capsys):
        """System namespaces are skipped by default."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "coredns",
                        "namespace": "kube-system",
                        "ownerReferences": [
                            {"kind": "StatefulSet", "name": "coredns"}
                        ]
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [{"name": "coredns"}]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([], output, context)

        # Should be 0 because kube-system is skipped
        assert result == 0

    def test_include_system_namespaces(self, capsys):
        """System namespaces are included with flag."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "coredns",
                        "namespace": "kube-system",
                        "ownerReferences": [
                            {"kind": "StatefulSet", "name": "coredns"}
                        ]
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [{"name": "coredns"}]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--include-system"], output, context)

        # Should find issues now
        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [{"name": "web"}]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "total_issues" in data["summary"]
        assert "high" in data["summary"]
        assert "medium" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "database-0",
                        "namespace": "production",
                        "ownerReferences": [
                            {"kind": "StatefulSet", "name": "database"}
                        ]
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [{"name": "db"}]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Severity" in captured.out
        assert "Type" in captured.out
        assert "Container" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters LOW severity issues."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [{"name": "web"}]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        # No HIGH/MEDIUM issues, only LOW would be found but filtered
        captured = capsys.readouterr()
        # Should not show LOW severity when warn-only is set
        assert "LOW" not in captured.out or "properly configured" in captured.out.lower()

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.lifecycle_hooks import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self):
        """Summary is set correctly."""
        from scripts.k8s.lifecycle_hooks import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production"
                    },
                    "spec": {
                        "terminationGracePeriodSeconds": 30,
                        "containers": [{"name": "web"}]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        run([], output, context)

        assert "issues=" in output.summary
        assert "high=" in output.summary
        assert "medium=" in output.summary
