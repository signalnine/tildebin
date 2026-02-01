"""Tests for serviceaccount_auditor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def serviceaccounts(fixtures_dir):
    """Load ServiceAccounts fixture."""
    return (fixtures_dir / "k8s" / "serviceaccounts.json").read_text()


@pytest.fixture
def pods_with_sa(fixtures_dir):
    """Load Pods with ServiceAccount references."""
    return (fixtures_dir / "k8s" / "pods_with_sa.json").read_text()


@pytest.fixture
def clusterrolebindings(fixtures_dir):
    """Load ClusterRoleBindings fixture."""
    return (fixtures_dir / "k8s" / "clusterrolebindings.json").read_text()


@pytest.fixture
def rolebindings(fixtures_dir):
    """Load RoleBindings fixture."""
    return (fixtures_dir / "k8s" / "rolebindings.json").read_text()


@pytest.fixture
def empty_list():
    """Empty Kubernetes list."""
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": []})


class TestServiceaccountAuditor:
    """Tests for serviceaccount_auditor script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = serviceaccount_auditor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_issues_in_clean_cluster(self, mock_context, empty_list):
        """Returns 0 when no ServiceAccount issues found."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = serviceaccount_auditor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_issues"] == 0

    def test_detects_automount_enabled(
        self, mock_context, serviceaccounts, pods_with_sa, empty_list
    ):
        """Detects ServiceAccounts with automountServiceAccountToken enabled."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_with_sa,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = serviceaccount_auditor.run([], output, ctx)

        automount_issues = [i for i in output.data["issues"] if i["type"] == "automount_enabled"]
        assert len(automount_issues) > 0

    def test_detects_default_sa_usage(
        self, mock_context, serviceaccounts, pods_with_sa, empty_list
    ):
        """Detects pods using the default ServiceAccount."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_with_sa,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = serviceaccount_auditor.run([], output, ctx)

        default_issues = [i for i in output.data["issues"] if i["type"] == "default_sa_usage"]
        assert len(default_issues) > 0

    def test_detects_cluster_admin_binding(
        self, mock_context, serviceaccounts, pods_with_sa, clusterrolebindings, rolebindings
    ):
        """Detects ServiceAccounts bound to cluster-admin."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_with_sa,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): clusterrolebindings,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): rolebindings,
            }
        )
        output = Output()

        exit_code = serviceaccount_auditor.run([], output, ctx)

        assert exit_code == 1
        admin_issues = [i for i in output.data["issues"] if i["type"] == "cluster_admin_binding"]
        assert len(admin_issues) > 0

    def test_detects_unused_serviceaccounts(
        self, mock_context, serviceaccounts, empty_list
    ):
        """Detects unused ServiceAccounts."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): empty_list,  # No pods
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = serviceaccount_auditor.run([], output, ctx)

        unused_issues = [i for i in output.data["issues"] if i["type"] == "unused_serviceaccount"]
        assert len(unused_issues) > 0

    def test_skip_unused_flag(
        self, mock_context, serviceaccounts, empty_list
    ):
        """--skip-unused skips unused ServiceAccount checks."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = serviceaccount_auditor.run(["--skip-unused"], output, ctx)

        unused_issues = [i for i in output.data["issues"] if i["type"] == "unused_serviceaccount"]
        assert len(unused_issues) == 0

    def test_summary_includes_sa_count(
        self, mock_context, serviceaccounts, pods_with_sa, empty_list
    ):
        """Summary includes ServiceAccount count."""
        from scripts.k8s import serviceaccount_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_with_sa,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = serviceaccount_auditor.run([], output, ctx)

        assert "summary" in output.data
        assert output.data["summary"]["total_serviceaccounts"] > 0
