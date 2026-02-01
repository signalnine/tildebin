"""Tests for deployment_status script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import load_json_fixture


class TestDeploymentStatus:
    """Tests for deployment_status script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import deployment_status

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = deployment_status.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_deployments_healthy(self, mock_context, fixtures_dir):
        """Returns 0 when all deployments are healthy."""
        from scripts.k8s import deployment_status

        deployments = (fixtures_dir / "k8s" / "deployments_healthy.json").read_text()
        statefulsets = (fixtures_dir / "k8s" / "statefulsets_healthy.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): deployments,
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): statefulsets,
            }
        )
        output = Output()

        exit_code = deployment_status.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["unhealthy"] == 0
        assert output.data["summary"]["healthy"] == 3  # 2 deployments + 1 statefulset

    def test_unhealthy_deployments_return_1(self, mock_context, fixtures_dir):
        """Returns 1 when deployments have issues."""
        from scripts.k8s import deployment_status

        deployments = (fixtures_dir / "k8s" / "deployments_unhealthy.json").read_text()
        statefulsets = (fixtures_dir / "k8s" / "statefulsets_empty.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): deployments,
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): statefulsets,
            }
        )
        output = Output()

        exit_code = deployment_status.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["unhealthy"] == 2

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """Filters by namespace when specified."""
        from scripts.k8s import deployment_status

        deployments = (fixtures_dir / "k8s" / "deployments_healthy.json").read_text()
        statefulsets = (fixtures_dir / "k8s" / "statefulsets_empty.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "-n", "production"): deployments,
                ("kubectl", "get", "statefulsets", "-o", "json", "-n", "production"): statefulsets,
            }
        )
        output = Output()

        exit_code = deployment_status.run(["-n", "production"], output, ctx)

        assert exit_code == 0

    def test_warn_only_filters_healthy(self, mock_context, fixtures_dir):
        """--warn-only only shows unhealthy resources."""
        from scripts.k8s import deployment_status

        deployments = (fixtures_dir / "k8s" / "deployments_unhealthy.json").read_text()
        statefulsets = (fixtures_dir / "k8s" / "statefulsets_healthy.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): deployments,
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): statefulsets,
            }
        )
        output = Output()

        exit_code = deployment_status.run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # Only unhealthy resources should be in results
        for resource in output.data["resources"]:
            assert resource["healthy"] is False

    def test_verbose_includes_images(self, mock_context, fixtures_dir):
        """--verbose includes image information."""
        from scripts.k8s import deployment_status

        deployments = (fixtures_dir / "k8s" / "deployments_healthy.json").read_text()
        statefulsets = (fixtures_dir / "k8s" / "statefulsets_empty.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): deployments,
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): statefulsets,
            }
        )
        output = Output()

        exit_code = deployment_status.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "images" in output.data["resources"][0]
