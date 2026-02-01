"""Tests for network_policy_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def netpol_namespaces(fixtures_dir):
    """Load namespaces fixture."""
    return (fixtures_dir / "k8s" / "netpol_namespaces.json").read_text()


@pytest.fixture
def netpol_policies_proper(fixtures_dir):
    """Load proper network policies fixture."""
    return (fixtures_dir / "k8s" / "netpol_policies_proper.json").read_text()


@pytest.fixture
def netpol_policies_permissive(fixtures_dir):
    """Load permissive network policies fixture."""
    return (fixtures_dir / "k8s" / "netpol_policies_permissive.json").read_text()


@pytest.fixture
def netpol_pods(fixtures_dir):
    """Load pods fixture."""
    return (fixtures_dir / "k8s" / "netpol_pods.json").read_text()


class TestNetworkPolicyAudit:
    """Tests for network_policy_audit script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import network_policy_audit

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = network_policy_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_namespace_without_policies(self, mock_context, netpol_namespaces, netpol_pods):
        """Detects namespaces without network policies."""
        from scripts.k8s import network_policy_audit

        empty_policies = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): netpol_namespaces,
                ("kubectl", "get", "networkpolicies", "-o", "json",
                 "--all-namespaces"): empty_policies,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): netpol_pods,
            }
        )
        output = Output()

        exit_code = network_policy_audit.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["namespaces_without_policies"]) > 0
        ns_names = [n["namespace"] for n in output.data["namespaces_without_policies"]]
        assert "default" in ns_names or "production" in ns_names or "staging" in ns_names

    def test_proper_policies_pass(self, mock_context, netpol_namespaces, netpol_policies_proper):
        """Returns 0 when policies properly cover pods."""
        from scripts.k8s import network_policy_audit

        # Pods that match the policies
        matching_pods = json.dumps({
            "items": [{
                "metadata": {
                    "name": "web-abc123",
                    "namespace": "production",
                    "labels": {"app": "web"}
                }
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps({
                    "items": [{"metadata": {"name": "production"}}]
                }),
                ("kubectl", "get", "networkpolicies", "-o", "json",
                 "--all-namespaces"): netpol_policies_proper,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): matching_pods,
            }
        )
        output = Output()

        exit_code = network_policy_audit.run([], output, ctx)

        # default-deny covers all pods in namespace
        assert exit_code == 0
        assert output.data["policy_count"] == 2

    def test_permissive_policies_detected(
        self, mock_context, netpol_namespaces, netpol_policies_permissive, netpol_pods
    ):
        """Detects overly permissive network policies."""
        from scripts.k8s import network_policy_audit

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps({
                    "items": [{"metadata": {"name": "staging"}}]
                }),
                ("kubectl", "get", "networkpolicies", "-o", "json",
                 "--all-namespaces"): netpol_policies_permissive,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): netpol_pods,
            }
        )
        output = Output()

        exit_code = network_policy_audit.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["overly_permissive_policies"]) > 0
        policy_names = [p["policy"] for p in output.data["overly_permissive_policies"]]
        assert "allow-all-ingress" in policy_names

    def test_unprotected_pods_detected(self, mock_context):
        """Detects pods not covered by network policies."""
        from scripts.k8s import network_policy_audit

        # Policy only covers app=web
        policies = json.dumps({
            "items": [{
                "metadata": {"name": "web-policy", "namespace": "production"},
                "spec": {
                    "podSelector": {"matchLabels": {"app": "web"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"podSelector": {}}]}]
                }
            }]
        })

        # Pod with app=api is not covered
        pods = json.dumps({
            "items": [
                {"metadata": {"name": "web-pod", "namespace": "production",
                              "labels": {"app": "web"}}},
                {"metadata": {"name": "api-pod", "namespace": "production",
                              "labels": {"app": "api"}}}
            ]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps({
                    "items": [{"metadata": {"name": "production"}}]
                }),
                ("kubectl", "get", "networkpolicies", "-o", "json",
                 "--all-namespaces"): policies,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = network_policy_audit.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["unprotected_pods"]) > 0
        unprotected = [p["pod"] for p in output.data["unprotected_pods"]]
        assert "api-pod" in unprotected

    def test_specific_namespace_audit(self, mock_context):
        """Can audit specific namespace."""
        from scripts.k8s import network_policy_audit

        policies = json.dumps({
            "items": [{
                "metadata": {"name": "deny-all", "namespace": "staging"},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
            }]
        })

        pods = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "networkpolicies", "-o", "json",
                 "-n", "staging"): policies,
                ("kubectl", "get", "pods", "-o", "json",
                 "-n", "staging"): pods,
            }
        )
        output = Output()

        exit_code = network_policy_audit.run(["-n", "staging"], output, ctx)

        assert exit_code == 0
        assert len(output.data["deny_all_policies"]) == 1

    def test_deny_all_policy_recorded(self, mock_context):
        """Records deny-all policies as informational."""
        from scripts.k8s import network_policy_audit

        deny_all_policy = json.dumps({
            "items": [{
                "metadata": {"name": "deny-all", "namespace": "production"},
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress", "Egress"]
                }
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps({
                    "items": [{"metadata": {"name": "production"}}]
                }),
                ("kubectl", "get", "networkpolicies", "-o", "json",
                 "--all-namespaces"): deny_all_policy,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): json.dumps({"items": []}),
            }
        )
        output = Output()

        exit_code = network_policy_audit.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["deny_all_policies"]) == 1
        assert output.data["deny_all_policies"][0]["policy"] == "deny-all"
