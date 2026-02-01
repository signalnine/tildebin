"""Tests for orphaned_resources_finder script."""

import json
import pytest

from boxctl.core.output import Output


class TestOrphanedResourcesFinder:
    """Tests for orphaned_resources_finder script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import orphaned_resources_finder

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = orphaned_resources_finder.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_orphaned_resources(self, mock_context, fixtures_dir):
        """Returns 0 when no orphaned resources found."""
        from scripts.k8s import orphaned_resources_finder

        pods = (fixtures_dir / "k8s" / "pods_with_configmaps.json").read_text()
        configmaps = (fixtures_dir / "k8s" / "configmaps_healthy.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pod", "-o", "json", "--all-namespaces"): pods,
                ("kubectl", "get", "configmap", "-o", "json", "--all-namespaces"): configmaps,
                ("kubectl", "get", "secret", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "serviceaccount", "-o", "json", "--all-namespaces"): empty,
            }
        )
        output = Output()

        exit_code = orphaned_resources_finder.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_orphaned"] == 0

    def test_orphaned_configmap_detected(self, mock_context, fixtures_dir):
        """Detects ConfigMaps not referenced by any pod."""
        from scripts.k8s import orphaned_resources_finder

        pods = (fixtures_dir / "k8s" / "orphaned_pods.json").read_text()
        configmaps = (fixtures_dir / "k8s" / "orphaned_configmaps.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pod", "-o", "json", "--all-namespaces"): pods,
                ("kubectl", "get", "configmap", "-o", "json", "--all-namespaces"): configmaps,
                ("kubectl", "get", "secret", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "serviceaccount", "-o", "json", "--all-namespaces"): empty,
            }
        )
        output = Output()

        exit_code = orphaned_resources_finder.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["orphaned_configmaps"] > 0

    def test_orphaned_secret_detected(self, mock_context, fixtures_dir):
        """Detects Secrets not referenced by any pod."""
        from scripts.k8s import orphaned_resources_finder

        pods = (fixtures_dir / "k8s" / "orphaned_pods.json").read_text()
        secrets = (fixtures_dir / "k8s" / "orphaned_secrets.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pod", "-o", "json", "--all-namespaces"): pods,
                ("kubectl", "get", "configmap", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "secret", "-o", "json", "--all-namespaces"): secrets,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "serviceaccount", "-o", "json", "--all-namespaces"): empty,
            }
        )
        output = Output()

        exit_code = orphaned_resources_finder.run([], output, ctx)

        assert exit_code == 1
        # Should have 1 orphaned secret (orphaned-secret), default-token is skipped
        assert output.data["summary"]["orphaned_secrets"] >= 1

    def test_orphaned_pvc_detected(self, mock_context, fixtures_dir):
        """Detects PVCs not mounted by any pod."""
        from scripts.k8s import orphaned_resources_finder

        pods = (fixtures_dir / "k8s" / "orphaned_pods.json").read_text()
        pvcs = (fixtures_dir / "k8s" / "orphaned_pvcs.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pod", "-o", "json", "--all-namespaces"): pods,
                ("kubectl", "get", "configmap", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "secret", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs,
                ("kubectl", "get", "serviceaccount", "-o", "json", "--all-namespaces"): empty,
            }
        )
        output = Output()

        exit_code = orphaned_resources_finder.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["orphaned_pvcs"] == 1  # orphaned-pvc

    def test_orphaned_serviceaccount_detected(self, mock_context, fixtures_dir):
        """Detects ServiceAccounts not used by any pod."""
        from scripts.k8s import orphaned_resources_finder

        pods = (fixtures_dir / "k8s" / "orphaned_pods.json").read_text()
        sas = (fixtures_dir / "k8s" / "orphaned_serviceaccounts.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pod", "-o", "json", "--all-namespaces"): pods,
                ("kubectl", "get", "configmap", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "secret", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "serviceaccount", "-o", "json", "--all-namespaces"): sas,
            }
        )
        output = Output()

        exit_code = orphaned_resources_finder.run([], output, ctx)

        assert exit_code == 1
        # Should detect unused-sa (default is skipped, app-sa is used)
        assert output.data["summary"]["orphaned_serviceaccounts"] == 1

    def test_skip_configmaps_flag(self, mock_context, fixtures_dir):
        """--skip-configmaps skips ConfigMap check."""
        from scripts.k8s import orphaned_resources_finder

        pods = (fixtures_dir / "k8s" / "orphaned_pods.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pod", "-o", "json", "--all-namespaces"): pods,
                ("kubectl", "get", "secret", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): empty,
                ("kubectl", "get", "serviceaccount", "-o", "json", "--all-namespaces"): empty,
            }
        )
        output = Output()

        exit_code = orphaned_resources_finder.run(["--skip-configmaps"], output, ctx)

        # ConfigMaps should not be checked
        assert output.data["summary"]["orphaned_configmaps"] == 0

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """--namespace filters to specific namespace."""
        from scripts.k8s import orphaned_resources_finder

        pods = (fixtures_dir / "k8s" / "orphaned_pods.json").read_text()
        empty = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pod", "-o", "json", "-n", "production"): pods,
                ("kubectl", "get", "configmap", "-o", "json", "-n", "production"): empty,
                ("kubectl", "get", "secret", "-o", "json", "-n", "production"): empty,
                ("kubectl", "get", "pvc", "-o", "json", "-n", "production"): empty,
                ("kubectl", "get", "serviceaccount", "-o", "json", "-n", "production"): empty,
            }
        )
        output = Output()

        exit_code = orphaned_resources_finder.run(["-n", "production"], output, ctx)

        assert exit_code in (0, 1)
