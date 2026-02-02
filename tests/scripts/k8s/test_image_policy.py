"""Tests for k8s image_policy script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestImagePolicy:
    """Tests for image_policy."""

    def get_workloads_fixture(self, with_violations: bool = False) -> dict:
        """Generate workloads fixture data."""
        if with_violations:
            return {
                "items": [
                    {
                        "metadata": {
                            "name": "bad-deploy",
                            "namespace": "default",
                        },
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        {
                                            "name": "app",
                                            "image": "myregistry.io/app:latest",
                                        }
                                    ]
                                }
                            }
                        },
                    }
                ]
            }
        else:
            return {
                "items": [
                    {
                        "metadata": {
                            "name": "good-deploy",
                            "namespace": "default",
                        },
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        {
                                            "name": "app",
                                            "image": "gcr.io/myproject/app@sha256:abc123",
                                        }
                                    ]
                                }
                            }
                        },
                    }
                ]
            }

    def test_compliant_images(self, capsys):
        """Compliant images return exit code 0."""
        from scripts.k8s.image_policy import run

        workloads = self.get_workloads_fixture(with_violations=False)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert "compliant=1" in output.summary

    def test_violations_detected(self, capsys):
        """Policy violations return exit code 1."""
        from scripts.k8s.image_policy import run

        workloads = self.get_workloads_fixture(with_violations=True)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Violation" in captured.out or "violations" in output.summary

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.image_policy import run

        workloads = self.get_workloads_fixture(with_violations=False)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert isinstance(data, list)
        assert len(data) > 0
        assert "namespace" in data[0]
        assert "image" in data[0]
        assert "violations" in data[0]
        assert "compliant" in data[0]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.image_policy import run

        workloads = self.get_workloads_fixture(with_violations=False)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out
        assert "RESOURCE" in captured.out
        assert "CONTAINER" in captured.out
        assert "STATUS" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters compliant images."""
        from scripts.k8s.image_policy import run

        workloads = self.get_workloads_fixture(with_violations=False)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--warn-only", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        # Should be empty since all are compliant
        assert len(data) == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.image_policy import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter restricts output."""
        from scripts.k8s.image_policy import run

        workloads = self.get_workloads_fixture(with_violations=False)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "-n", "production"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "-n", "production"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "-n", "production"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "-n", "production"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0

    def test_no_require_digest(self, capsys):
        """--no-require-digest skips digest check."""
        from scripts.k8s.image_policy import run

        # Image with mutable tag but no digest requirement
        workloads = {
            "items": [
                {
                    "metadata": {"name": "test-deploy", "namespace": "default"},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"name": "app", "image": "gcr.io/myproject/app:v1.0"}
                                ]
                            }
                        }
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--no-require-digest"], output, context)

        # Should pass since v1.0 is not a mutable tag and registry is trusted
        assert result == 0

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.image_policy import run

        workloads = self.get_workloads_fixture(with_violations=False)

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(workloads),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "images=" in output.summary
        assert "compliant=" in output.summary
        assert "violations=" in output.summary


class TestParseImageRef:
    """Tests for parse_image_ref function."""

    def test_simple_image(self):
        """Parse simple image name."""
        from scripts.k8s.image_policy import parse_image_ref

        result = parse_image_ref("nginx")
        assert result["registry"] == "docker.io"
        assert result["repository"] == "library/nginx"
        assert result["tag"] == "latest"
        assert result["is_pinned"] is False

    def test_image_with_tag(self):
        """Parse image with tag."""
        from scripts.k8s.image_policy import parse_image_ref

        result = parse_image_ref("nginx:1.19")
        assert result["tag"] == "1.19"
        assert result["is_pinned"] is False

    def test_image_with_digest(self):
        """Parse image with digest."""
        from scripts.k8s.image_policy import parse_image_ref

        result = parse_image_ref("nginx@sha256:abc123")
        assert result["digest"] == "sha256:abc123"
        assert result["is_pinned"] is True

    def test_full_registry_path(self):
        """Parse full registry path."""
        from scripts.k8s.image_policy import parse_image_ref

        result = parse_image_ref("gcr.io/myproject/myapp:v1.0")
        assert result["registry"] == "gcr.io"
        assert result["repository"] == "myproject/myapp"
        assert result["tag"] == "v1.0"
