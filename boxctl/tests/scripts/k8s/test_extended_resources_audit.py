"""Tests for extended_resources_audit script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import load_json_fixture


class TestExtendedResourcesAudit:
    """Tests for extended_resources_audit script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import extended_resources_audit

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = extended_resources_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_extended_resources(self, mock_context, fixtures_dir):
        """Returns 0 when cluster has no extended resources."""
        from scripts.k8s import extended_resources_audit

        nodes_data = (fixtures_dir / "k8s" / "nodes_healthy.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_no_extended_resources.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = extended_resources_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_nodes_with_extended"] == 0

    def test_gpu_nodes_detected(self, mock_context, fixtures_dir):
        """Detects nodes with GPU resources."""
        from scripts.k8s import extended_resources_audit

        nodes_data = (fixtures_dir / "k8s" / "nodes_with_extended_resources.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_using_gpus.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = extended_resources_audit.run(["--verbose"], output, ctx)

        # Should have 2 GPU nodes
        assert output.data["summary"]["total_nodes_with_extended"] == 2
        assert "nvidia.com/gpu" in output.data["summary"]["resources"]

    def test_pending_pod_detected(self, mock_context, fixtures_dir):
        """Detects pending pods requesting extended resources."""
        from scripts.k8s import extended_resources_audit

        nodes_data = (fixtures_dir / "k8s" / "nodes_with_extended_resources.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_using_gpus.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = extended_resources_audit.run([], output, ctx)

        # Should return 1 because there's a pending pod
        assert exit_code == 1
        pending_issues = [i for i in output.data["issues"] if i["type"] == "PENDING_POD"]
        assert len(pending_issues) > 0

    def test_warn_only_filters_issues(self, mock_context, fixtures_dir):
        """--warn-only only shows WARNING severity issues."""
        from scripts.k8s import extended_resources_audit

        nodes_data = (fixtures_dir / "k8s" / "nodes_with_extended_resources.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_using_gpus.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = extended_resources_audit.run(["--warn-only"], output, ctx)

        # All issues should be WARNING severity
        for issue in output.data["issues"]:
            assert issue["severity"] == "WARNING"

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """--namespace filters pods to specific namespace."""
        from scripts.k8s import extended_resources_audit

        nodes_data = (fixtures_dir / "k8s" / "nodes_with_extended_resources.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_using_gpus.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "-n", "ml-workloads"): pods_data,
            }
        )
        output = Output()

        exit_code = extended_resources_audit.run(["-n", "ml-workloads"], output, ctx)

        # Should work and use namespace filter
        assert exit_code in (0, 1)

    def test_verbose_includes_pod_details(self, mock_context, fixtures_dir):
        """--verbose includes pod details in output."""
        from scripts.k8s import extended_resources_audit

        nodes_data = (fixtures_dir / "k8s" / "nodes_with_extended_resources.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_using_gpus.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = extended_resources_audit.run(["--verbose"], output, ctx)

        # Verbose mode should include pods details
        assert "pods" in output.data
        assert len(output.data["pods"]) > 0
