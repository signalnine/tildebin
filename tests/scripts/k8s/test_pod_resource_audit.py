"""Tests for pod_resource_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestPodResourceAudit:
    """Tests for pod_resource_audit."""

    def test_no_pods(self, capsys):
        """No pods returns exit code 0."""
        from scripts.k8s.pod_resource_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_empty.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_healthy_pods(self, capsys):
        """Healthy pods returns exit code 0."""
        from scripts.k8s.pod_resource_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_no_restarts.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_pods_with_issues(self, capsys):
        """Pods with issues returns exit code 1."""
        from scripts.k8s.pod_resource_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_resource_issues.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "issues" in captured.out.lower() or "OOMKilled" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.pod_resource_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_resource_issues.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_pods" in data
        assert "pods_with_issues" in data
        assert "pods" in data

    def test_warn_only_filter(self, capsys):
        """Warn-only filter shows only pods with issues."""
        from scripts.k8s.pod_resource_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_resource_issues.json"
                ),
            },
        )
        output = Output()

        result = run(["--warn-only", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # All returned pods should have issues
        for pod in data["pods"]:
            assert len(pod["issues"]) > 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.pod_resource_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_check_pod_resources_no_limits(self):
        """Pods without limits are flagged."""
        from scripts.k8s.pod_resource_audit import check_pod_resources

        pod = {"spec": {"containers": [{"name": "app", "resources": {}}]}}

        issues = check_pod_resources(pod)

        assert len(issues) > 0
        assert any("no resource" in i.lower() for i in issues)

    def test_check_pod_status_oomkilled(self):
        """OOMKilled status is detected."""
        from scripts.k8s.pod_resource_audit import check_pod_status

        pod = {
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {
                        "name": "app",
                        "restartCount": 3,
                        "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}},
                        "state": {"running": {}},
                    }
                ],
            }
        }

        issues = check_pod_status(pod)

        assert any("OOMKilled" in i for i in issues)

    def test_check_pod_status_evicted(self):
        """Evicted status is detected."""
        from scripts.k8s.pod_resource_audit import check_pod_status

        pod = {
            "status": {
                "phase": "Failed",
                "reason": "Evicted",
                "message": "The node was low on resource: memory.",
                "containerStatuses": [],
            }
        }

        issues = check_pod_status(pod)

        assert any("evicted" in i.lower() for i in issues)
