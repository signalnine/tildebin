"""Tests for k8s image_pull script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestImagePull:
    """Tests for image_pull."""

    def get_pods_with_issues(self) -> dict:
        """Generate pods fixture with image pull issues."""
        return {
            "items": [
                {
                    "metadata": {"name": "failing-pod", "namespace": "default"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "app",
                                "image": "myregistry.io/app:latest",
                                "state": {
                                    "waiting": {
                                        "reason": "ImagePullBackOff",
                                        "message": "Back-off pulling image",
                                    }
                                },
                            }
                        ]
                    },
                }
            ]
        }

    def get_pods_healthy(self) -> dict:
        """Generate healthy pods fixture."""
        return {
            "items": [
                {
                    "metadata": {"name": "healthy-pod", "namespace": "default"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "app",
                                "image": "nginx:latest",
                                "state": {"running": {"startedAt": "2024-01-01T00:00:00Z"}},
                            }
                        ]
                    },
                }
            ]
        }

    def get_events_empty(self) -> dict:
        """Empty events fixture."""
        return {"items": []}

    def test_no_issues(self, capsys):
        """No issues returns exit code 0."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_healthy()
                ),
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_events_empty()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No image pull issues" in captured.out

    def test_issues_detected(self, capsys):
        """Image pull issues return exit code 1."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_issues()
                ),
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_events_empty()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert "errors=1" in output.summary

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_issues()
                ),
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_events_empty()
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "total_issues" in data["summary"]
        assert len(data["issues"]) > 0

    def test_table_output(self, capsys):
        """Table output includes summary."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_issues()
                ),
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_events_empty()
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Image Pull Issues Summary" in captured.out
        assert "Type" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter restricts output."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): json.dumps(
                    self.get_pods_healthy()
                ),
                ("kubectl", "get", "events", "-o", "json", "-n", "production"): json.dumps(
                    self.get_events_empty()
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0

    def test_verbose_output(self, capsys):
        """Verbose output shows detailed information."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_with_issues()
                ),
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_events_empty()
                ),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Detailed issues" in captured.out
        assert "Namespace:" in captured.out
        assert "Pod:" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.image_pull import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_pods_healthy()
                ),
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_events_empty()
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "issues=" in output.summary
        assert "errors=" in output.summary
