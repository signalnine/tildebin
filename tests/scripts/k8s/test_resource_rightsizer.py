"""Tests for k8s resource_rightsizer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestResourceRightsizer:
    """Tests for resource_rightsizer."""

    def test_well_sized_resources(self, capsys):
        """Well-sized resources return exit code 0."""
        from scripts.k8s.resource_rightsizer import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "efficient", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "200m", "memory": "256Mi"},
                                },
                            }
                        ]
                    },
                    "status": {"phase": "Running"},
                }
            ]
        }

        # Metrics showing 50% utilization
        metrics_output = "default efficient 50m 64Mi"

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(pods),
                ("kubectl", "top", "pods", "--no-headers", "--all-namespaces"): metrics_output,
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_over_provisioned(self, capsys):
        """Over-provisioned resources return exit code 1."""
        from scripts.k8s.resource_rightsizer import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "wasteful", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "resources": {
                                    "requests": {"cpu": "1000m", "memory": "1Gi"},
                                    "limits": {"cpu": "2000m", "memory": "2Gi"},
                                },
                            }
                        ]
                    },
                    "status": {"phase": "Running"},
                }
            ]
        }

        # Metrics showing 5% utilization
        metrics_output = "default wasteful 50m 50Mi"

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(pods),
                ("kubectl", "top", "pods", "--no-headers", "--all-namespaces"): metrics_output,
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert result == 1
        assert "over" in captured.out.lower() or "OVER" in captured.out

    def test_no_requests(self, capsys):
        """Pods without requests return exit code 1."""
        from scripts.k8s.resource_rightsizer import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "no-requests", "namespace": "default"},
                    "spec": {"containers": [{"name": "app"}]},
                    "status": {"phase": "Running"},
                }
            ]
        }

        metrics_output = "default no-requests 50m 64Mi"

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(pods),
                ("kubectl", "top", "pods", "--no-headers", "--all-namespaces"): metrics_output,
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert result == 1
        assert "request" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.resource_rightsizer import run

        pods = {
            "items": [
                {
                    "metadata": {"name": "test", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"}
                                },
                            }
                        ]
                    },
                    "status": {"phase": "Running"},
                }
            ]
        }

        metrics_output = "default test 50m 64Mi"

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-o",
                    "json",
                    "--all-namespaces",
                ): json.dumps(pods),
                ("kubectl", "top", "pods", "--no-headers", "--all-namespaces"): metrics_output,
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "potential_savings" in data
        assert "categories" in data

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.resource_rightsizer import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
