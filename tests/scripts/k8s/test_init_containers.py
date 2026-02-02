"""Tests for k8s init_containers script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestInitContainers:
    """Tests for init_containers."""

    def get_pods_with_init_issues(self) -> dict:
        """Generate pods with init container issues."""
        return {
            "items": [
                {
                    "metadata": {
                        "name": "failing-pod",
                        "namespace": "default",
                        "creationTimestamp": "2024-01-01T00:00:00Z",
                    },
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init-db",
                                "image": "busybox:latest",
                                "command": ["sh", "-c", "exit 1"],
                            }
                        ],
                        "containers": [{"name": "app", "image": "nginx:latest"}],
                    },
                    "status": {
                        "phase": "Pending",
                        "initContainerStatuses": [
                            {
                                "name": "init-db",
                                "state": {
                                    "waiting": {
                                        "reason": "CrashLoopBackOff",
                                        "message": "Back-off restarting failed container",
                                    }
                                },
                                "restartCount": 5,
                            }
                        ],
                    },
                }
            ]
        }

    def get_pods_healthy_init(self) -> dict:
        """Generate pods with healthy init containers."""
        return {
            "items": [
                {
                    "metadata": {
                        "name": "healthy-pod",
                        "namespace": "default",
                        "creationTimestamp": "2024-01-01T00:00:00Z",
                    },
                    "spec": {
                        "initContainers": [
                            {
                                "name": "init-db",
                                "image": "busybox:latest",
                                "command": ["sh", "-c", "echo done"],
                            }
                        ],
                        "containers": [{"name": "app", "image": "nginx:latest"}],
                    },
                    "status": {
                        "phase": "Running",
                        "initContainerStatuses": [
                            {
                                "name": "init-db",
                                "state": {
                                    "terminated": {
                                        "exitCode": 0,
                                        "reason": "Completed",
                                    }
                                },
                                "restartCount": 0,
                            }
                        ],
                    },
                }
            ]
        }

    def get_pods_no_init(self) -> dict:
        """Generate pods without init containers."""
        return {
            "items": [
                {
                    "metadata": {"name": "simple-pod", "namespace": "default"},
                    "spec": {
                        "containers": [{"name": "app", "image": "nginx:latest"}],
                    },
                    "status": {"phase": "Running"},
                }
            ]
        }

    def test_no_issues(self, capsys):
        """Healthy init containers return exit code 0."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_healthy_init()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_issues_detected(self, capsys):
        """Init container issues return exit code 1."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_init_issues()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CrashLoopBackOff" in captured.out or "init_crashloop" in captured.out

    def test_no_init_containers(self, capsys):
        """No init containers returns exit code 0."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_no_init()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No pods with init containers" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_init_issues()
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "pods" in data
        assert "total_pods" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_init_issues()
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Namespace" in captured.out
        assert "Pod" in captured.out
        assert "Container" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter restricts output."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): json.dumps(
                    self.get_pods_healthy_init()
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0

    def test_verbose_output(self, capsys):
        """Verbose output shows remediation suggestions."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_init_issues()
                ),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Remediation" in captured.out

    def test_severity_filter(self, capsys):
        """Severity filter restricts output."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_init_issues()
                ),
            },
        )
        output = Output()

        result = run(["--severity", "critical"], output, context)

        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.init_containers import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_healthy_init()
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "pods=" in output.summary
        assert "with_issues=" in output.summary
