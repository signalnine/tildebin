"""Tests for configmap_audit script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


class TestConfigmapAudit:
    """Tests for configmap_audit script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import configmap_audit

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = configmap_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_healthy_configmaps_no_issues(self, mock_context, fixtures_dir):
        """Returns 0 when configmaps are healthy and referenced."""
        from scripts.k8s import configmap_audit

        configmaps = (fixtures_dir / "k8s" / "configmaps_healthy.json").read_text()
        pods = (fixtures_dir / "k8s" / "pods_with_configmaps.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): configmaps,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = configmap_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["approaching_limit"] == 0
        assert output.data["summary"]["missing_keys"] == 0

    def test_detects_empty_configmaps(self, mock_context, fixtures_dir):
        """Detects empty ConfigMaps."""
        from scripts.k8s import configmap_audit

        configmaps = (fixtures_dir / "k8s" / "configmaps_issues.json").read_text()
        pods = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): configmaps,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = configmap_audit.run([], output, ctx)

        assert output.data["summary"]["empty"] > 0

    def test_detects_unused_configmaps(self, mock_context, fixtures_dir):
        """Detects unused ConfigMaps."""
        from scripts.k8s import configmap_audit

        configmaps = (fixtures_dir / "k8s" / "configmaps_issues.json").read_text()
        pods = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): configmaps,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = configmap_audit.run([], output, ctx)

        assert output.data["summary"]["unused"] > 0

    def test_detects_default_namespace(self, mock_context, fixtures_dir):
        """Detects ConfigMaps in default namespace."""
        from scripts.k8s import configmap_audit

        configmaps = (fixtures_dir / "k8s" / "configmaps_issues.json").read_text()
        pods = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): configmaps,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = configmap_audit.run([], output, ctx)

        assert output.data["summary"]["default_namespace"] > 0

    def test_no_configmaps_returns_warning(self, mock_context):
        """Returns 0 with warning when no ConfigMaps found."""
        from scripts.k8s import configmap_audit

        empty_list = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = configmap_audit.run([], output, ctx)

        assert exit_code == 0
        assert len(output.warnings) > 0

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """Filters by namespace when specified."""
        from scripts.k8s import configmap_audit

        configmaps = (fixtures_dir / "k8s" / "configmaps_healthy.json").read_text()
        pods = (fixtures_dir / "k8s" / "pods_with_configmaps.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "configmaps", "-o", "json", "-n", "production"): configmaps,
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): pods,
            }
        )
        output = Output()

        exit_code = configmap_audit.run(["-n", "production"], output, ctx)

        assert exit_code == 0
