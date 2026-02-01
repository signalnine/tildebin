"""Tests for serviceaccount_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def sa_serviceaccounts(fixtures_dir):
    """Load ServiceAccounts fixture."""
    return (fixtures_dir / "k8s" / "sa_serviceaccounts.json").read_text()


@pytest.fixture
def sa_pods(fixtures_dir):
    """Load pods fixture."""
    return (fixtures_dir / "k8s" / "sa_pods.json").read_text()


@pytest.fixture
def sa_clusterrolebindings(fixtures_dir):
    """Load ClusterRoleBindings fixture."""
    return (fixtures_dir / "k8s" / "sa_clusterrolebindings.json").read_text()


@pytest.fixture
def sa_rolebindings(fixtures_dir):
    """Load RoleBindings fixture."""
    return (fixtures_dir / "k8s" / "sa_rolebindings.json").read_text()


class TestServiceaccountAudit:
    """Tests for serviceaccount_audit script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import serviceaccount_audit

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = serviceaccount_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_detects_cluster_admin_binding(
        self, mock_context, sa_serviceaccounts, sa_pods, sa_clusterrolebindings, sa_rolebindings
    ):
        """Detects ServiceAccounts bound to cluster-admin."""
        from scripts.k8s import serviceaccount_audit

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json",
                 "--all-namespaces"): sa_serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): sa_pods,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): sa_clusterrolebindings,
                ("kubectl", "get", "rolebindings", "-o", "json",
                 "--all-namespaces"): sa_rolebindings,
            }
        )
        output = Output()

        exit_code = serviceaccount_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["high_severity"] >= 1
        high_issues = [i for i in output.data["issues"] if i["severity"] == "HIGH"]
        assert any("cluster-admin" in i["detail"].lower() for i in high_issues)

    def test_detects_default_sa_usage(
        self, mock_context, sa_serviceaccounts, sa_pods, sa_rolebindings
    ):
        """Detects pods using default ServiceAccount."""
        from scripts.k8s import serviceaccount_audit

        empty_crb = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json",
                 "--all-namespaces"): sa_serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): sa_pods,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_crb,
                ("kubectl", "get", "rolebindings", "-o", "json",
                 "--all-namespaces"): sa_rolebindings,
            }
        )
        output = Output()

        exit_code = serviceaccount_audit.run([], output, ctx)

        assert exit_code == 1
        default_issues = [
            i for i in output.data["issues"]
            if i["type"] == "default_sa_usage"
        ]
        assert len(default_issues) > 0

    def test_detects_unused_serviceaccount(self, mock_context, sa_serviceaccounts, sa_rolebindings):
        """Detects ServiceAccounts with no pods using them."""
        from scripts.k8s import serviceaccount_audit

        empty_pods = json.dumps({"items": []})
        empty_crb = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json",
                 "--all-namespaces"): sa_serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): empty_pods,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_crb,
                ("kubectl", "get", "rolebindings", "-o", "json",
                 "--all-namespaces"): sa_rolebindings,
            }
        )
        output = Output()

        exit_code = serviceaccount_audit.run([], output, ctx)

        assert exit_code == 1
        unused_issues = [
            i for i in output.data["issues"]
            if i["type"] == "unused_serviceaccount"
        ]
        assert len(unused_issues) > 0
        # unused-sa in staging should be flagged
        assert any(i["serviceaccount"] == "unused-sa" for i in unused_issues)

    def test_skip_unused_flag(self, mock_context, sa_serviceaccounts, sa_rolebindings):
        """--skip-unused flag skips unused SA checks."""
        from scripts.k8s import serviceaccount_audit

        empty_pods = json.dumps({"items": []})
        empty_crb = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json",
                 "--all-namespaces"): sa_serviceaccounts,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): empty_pods,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_crb,
                ("kubectl", "get", "rolebindings", "-o", "json",
                 "--all-namespaces"): sa_rolebindings,
            }
        )
        output = Output()

        exit_code = serviceaccount_audit.run(["--skip-unused"], output, ctx)

        unused_issues = [
            i for i in output.data["issues"]
            if i["type"] == "unused_serviceaccount"
        ]
        assert len(unused_issues) == 0

    def test_detects_automount_enabled(self, mock_context, sa_pods, sa_rolebindings):
        """Detects automountServiceAccountToken enabled."""
        from scripts.k8s import serviceaccount_audit

        sa_with_automount = json.dumps({
            "items": [{
                "metadata": {"name": "my-sa", "namespace": "production"},
                "automountServiceAccountToken": True
            }]
        })

        pods_using_sa = json.dumps({
            "items": [{
                "metadata": {"name": "my-pod", "namespace": "production"},
                "spec": {
                    "serviceAccountName": "my-sa",
                    "automountServiceAccountToken": True
                }
            }]
        })

        empty_crb = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json",
                 "--all-namespaces"): sa_with_automount,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): pods_using_sa,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty_crb,
                ("kubectl", "get", "rolebindings", "-o", "json",
                 "--all-namespaces"): sa_rolebindings,
            }
        )
        output = Output()

        exit_code = serviceaccount_audit.run(["--skip-unused"], output, ctx)

        assert exit_code == 1
        automount_issues = [
            i for i in output.data["issues"]
            if i["type"] == "automount_enabled"
        ]
        assert len(automount_issues) > 0

    def test_specific_namespace_audit(self, mock_context):
        """Can audit specific namespace."""
        from scripts.k8s import serviceaccount_audit

        sa = json.dumps({
            "items": [{
                "metadata": {"name": "my-sa", "namespace": "staging"},
                "automountServiceAccountToken": False
            }]
        })
        empty = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json",
                 "-n", "staging"): sa,
                ("kubectl", "get", "pods", "-o", "json",
                 "-n", "staging"): empty,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty,
                ("kubectl", "get", "rolebindings", "-o", "json",
                 "-n", "staging"): empty,
            }
        )
        output = Output()

        exit_code = serviceaccount_audit.run(["-n", "staging", "--skip-unused"], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["serviceaccounts_checked"] == 1

    def test_no_issues_returns_zero(self, mock_context):
        """Returns 0 when no issues found."""
        from scripts.k8s import serviceaccount_audit

        sa = json.dumps({
            "items": [{
                "metadata": {"name": "secure-sa", "namespace": "production"},
                "automountServiceAccountToken": False
            }]
        })

        pods = json.dumps({
            "items": [{
                "metadata": {"name": "app-pod", "namespace": "production"},
                "spec": {
                    "serviceAccountName": "secure-sa",
                    "automountServiceAccountToken": False
                }
            }]
        })

        empty = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "serviceaccounts", "-o", "json",
                 "--all-namespaces"): sa,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): pods,
                ("kubectl", "get", "clusterrolebindings", "-o", "json"): empty,
                ("kubectl", "get", "rolebindings", "-o", "json",
                 "--all-namespaces"): empty,
            }
        )
        output = Output()

        exit_code = serviceaccount_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_issues"] == 0
