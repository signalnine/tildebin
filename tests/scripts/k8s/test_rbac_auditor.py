"""Tests for rbac_auditor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def clusterroles(fixtures_dir):
    """Load ClusterRoles fixture."""
    return (fixtures_dir / "k8s" / "clusterroles.json").read_text()


@pytest.fixture
def roles(fixtures_dir):
    """Load Roles fixture."""
    return (fixtures_dir / "k8s" / "roles.json").read_text()


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


class TestRbacAuditor:
    """Tests for rbac_auditor script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import rbac_auditor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = rbac_auditor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_issues_in_clean_cluster(self, mock_context, empty_list):
        """Returns 0 when no RBAC issues found."""
        from scripts.k8s import rbac_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "clusterroles", "-o", "json"): empty_list,
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = rbac_auditor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_issues"] == 0

    def test_detects_wildcard_permissions(self, mock_context, clusterroles, roles, empty_list):
        """Detects roles with wildcard permissions."""
        from scripts.k8s import rbac_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "clusterroles", "-o", "json"): clusterroles,
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): roles,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = rbac_auditor.run([], output, ctx)

        assert exit_code == 1
        wildcard_issues = [i for i in output.data["issues"] if i["type"] == "wildcard_permissions"]
        assert len(wildcard_issues) > 0

    def test_detects_cluster_admin_binding(
        self, mock_context, empty_list, clusterrolebindings, rolebindings
    ):
        """Detects cluster-admin bindings."""
        from scripts.k8s import rbac_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "clusterroles", "-o", "json"): empty_list,
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): clusterrolebindings,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): rolebindings,
            }
        )
        output = Output()

        exit_code = rbac_auditor.run([], output, ctx)

        assert exit_code == 1
        admin_issues = [i for i in output.data["issues"] if i["type"] == "cluster_admin_binding"]
        assert len(admin_issues) >= 2  # User and ServiceAccount bindings

    def test_detects_anonymous_access(
        self, mock_context, empty_list, clusterrolebindings
    ):
        """Detects anonymous user access."""
        from scripts.k8s import rbac_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "clusterroles", "-o", "json"): empty_list,
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): clusterrolebindings,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = rbac_auditor.run([], output, ctx)

        assert exit_code == 1
        anon_issues = [i for i in output.data["issues"] if i["type"] == "anonymous_access"]
        assert len(anon_issues) > 0

    def test_detects_secrets_access(self, mock_context, clusterroles, empty_list):
        """Detects roles with secrets access."""
        from scripts.k8s import rbac_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "clusterroles", "-o", "json"): clusterroles,
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): empty_list,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_list,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): empty_list,
            }
        )
        output = Output()

        exit_code = rbac_auditor.run([], output, ctx)

        assert exit_code == 1
        secrets_issues = [i for i in output.data["issues"] if i["type"] == "sensitive_resource_access"]
        assert len(secrets_issues) > 0

    def test_summary_counts_by_severity(
        self, mock_context, clusterroles, roles, clusterrolebindings, rolebindings
    ):
        """Summary includes issue counts by severity."""
        from scripts.k8s import rbac_auditor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "clusterroles", "-o", "json"): clusterroles,
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): roles,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): clusterrolebindings,
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): rolebindings,
            }
        )
        output = Output()

        exit_code = rbac_auditor.run([], output, ctx)

        assert "summary" in output.data
        assert "high_severity" in output.data["summary"]
        assert "medium_severity" in output.data["summary"]
        assert output.data["summary"]["total_issues"] > 0
