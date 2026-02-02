"""Tests for k8s image_registry script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestImageRegistry:
    """Tests for image_registry."""

    def test_approved_registry(self, capsys):
        """Images from approved registries return exit code 0."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "gcr.io/my-project/web:v1",
                                "imageID": "gcr.io/my-project/web@sha256:abc123"
                            }
                        ]
                    }
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
        assert "compliant" in captured.out.lower()

    def test_unapproved_registry(self, capsys):
        """Images from unapproved registries return exit code 1."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "my-private-registry.com/web:v1",
                                "imageID": "my-private-registry.com/web@sha256:abc123"
                            }
                        ]
                    }
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
        assert "Unapproved" in captured.out or "violation" in captured.out.lower()

    def test_implicit_dockerhub(self, capsys):
        """Implicit docker.io images show violation."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "nginx:latest",
                                "imageID": "docker.io/library/nginx@sha256:abc123"
                            }
                        ]
                    }
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
        assert "Implicit docker.io" in captured.out

    def test_custom_approved_registry(self, capsys):
        """Custom approved registry works."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "my-private-registry.com/web:v1",
                                "imageID": "my-private-registry.com/web@sha256:abc123"
                            }
                        ]
                    }
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

        result = run(["--approved-registry", "my-private-registry.com"], output, context)

        assert result == 0

    def test_skip_approval_check(self, capsys):
        """Skip approval check shows stats only."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "random-registry.com/web:v1",
                                "imageID": "random-registry.com/web@sha256:abc123"
                            }
                        ]
                    }
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

        result = run(["--skip-approval-check"], output, context)

        # No violations when skipping approval check
        assert result == 0

    def test_block_public_in_prod(self, capsys):
        """Block public in prod flags docker hub in production."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "docker.io/library/nginx:latest",
                                "imageID": "docker.io/library/nginx@sha256:abc123"
                            }
                        ]
                    }
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

        result = run(["--block-public-in-prod", "--skip-approval-check"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Public registry in production" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "gcr.io/my-project/web:v1",
                                "imageID": "gcr.io/my-project/web@sha256:abc123"
                            }
                        ]
                    }
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

        assert "findings" in data
        assert "registry_stats" in data
        assert "violations" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "gcr.io/my-project/web:v1",
                                "imageID": "gcr.io/my-project/web@sha256:abc123"
                            }
                        ]
                    }
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
        assert "NAMESPACE" in captured.out
        assert "POD" in captured.out
        assert "CONTAINER" in captured.out
        assert "REGISTRY" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters compliant images."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "gcr.io/my-project/web:v1",
                                "imageID": "gcr.io/my-project/web@sha256:abc123"
                            }
                        ]
                    }
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

        assert result == 0
        captured = capsys.readouterr()
        assert "No registry policy violations detected" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.image_registry import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_no_pods(self, capsys):
        """No pods returns exit code 0."""
        from scripts.k8s.image_registry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No running pods found" in captured.out

    def test_init_containers_checked(self, capsys):
        """Init containers are also checked."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "gcr.io/my-project/web:v1",
                                "imageID": "gcr.io/my-project/web@sha256:abc123"
                            }
                        ],
                        "initContainerStatuses": [
                            {
                                "name": "init",
                                "image": "bad-registry.com/init:v1",
                                "imageID": "bad-registry.com/init@sha256:abc123"
                            }
                        ]
                    }
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
        assert "bad-registry.com" in captured.out

    def test_summary_set(self):
        """Summary is set correctly."""
        from scripts.k8s.image_registry import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "web-pod", "namespace": "production"},
                    "status": {
                        "containerStatuses": [
                            {
                                "name": "web",
                                "image": "gcr.io/my-project/web:v1",
                                "imageID": "gcr.io/my-project/web@sha256:abc123"
                            }
                        ]
                    }
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

        assert "images=" in output.summary
        assert "compliant=" in output.summary
        assert "violations=" in output.summary
