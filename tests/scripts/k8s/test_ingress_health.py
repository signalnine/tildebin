"""Tests for ingress_health script."""

import pytest
import json
from pathlib import Path

from boxctl.core.output import Output


class TestIngressHealth:
    """Tests for ingress_health script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import ingress_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = ingress_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_ingresses_healthy(self, mock_context, fixtures_dir):
        """Returns 0 when all ingresses are healthy."""
        from scripts.k8s import ingress_health

        ingresses = (fixtures_dir / "k8s" / "ingresses_healthy.json").read_text()
        
        # Mock secret response
        secret_response = json.dumps({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "example-tls", "namespace": "production"},
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
                "tls.key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"
            }
        })
        
        # Mock endpoint response
        endpoint_response = json.dumps({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": {"name": "web-service", "namespace": "production"},
            "subsets": [{"addresses": [{"ip": "10.0.0.1"}]}]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "ingress", "-o", "json", "--all-namespaces"): ingresses,
                ("kubectl", "get", "secret", "example-tls", "-n", "production", "-o", "json"): secret_response,
                ("kubectl", "get", "endpoints", "web-service", "-n", "production", "-o", "json"): endpoint_response,
            }
        )
        output = Output()

        exit_code = ingress_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["with_issues"] == 0

    def test_ingresses_with_issues(self, mock_context, fixtures_dir):
        """Returns 1 when ingresses have issues."""
        from scripts.k8s import ingress_health

        ingresses = (fixtures_dir / "k8s" / "ingresses_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "ingress", "-o", "json", "--all-namespaces"): ingresses,
                # Missing secret will trigger issue
                ("kubectl", "get", "secret", "missing-tls", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "broken-service", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "web-service", "-n", "staging", "-o", "json"): "",
            }
        )
        output = Output()

        exit_code = ingress_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["with_issues"] > 0

    def test_detects_missing_tls_secret(self, mock_context, fixtures_dir):
        """Detects ingresses with missing TLS secrets."""
        from scripts.k8s import ingress_health

        ingresses = (fixtures_dir / "k8s" / "ingresses_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "ingress", "-o", "json", "--all-namespaces"): ingresses,
                ("kubectl", "get", "secret", "missing-tls", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "broken-service", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "web-service", "-n", "staging", "-o", "json"): "",
            }
        )
        output = Output()

        exit_code = ingress_health.run([], output, ctx)

        # Should detect missing TLS secret
        broken_ingress = next(
            (i for i in output.data["ingresses"] if i["name"] == "broken-ingress"),
            None
        )
        assert broken_ingress is not None
        assert any("TLS secret" in issue for issue in broken_ingress["issues"])

    def test_detects_no_tls_configuration(self, mock_context, fixtures_dir):
        """Detects ingresses without TLS configuration."""
        from scripts.k8s import ingress_health

        ingresses = (fixtures_dir / "k8s" / "ingresses_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "ingress", "-o", "json", "--all-namespaces"): ingresses,
                ("kubectl", "get", "secret", "missing-tls", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "broken-service", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "web-service", "-n", "staging", "-o", "json"): '{"subsets": [{"addresses": [{"ip": "10.0.0.1"}]}]}',
            }
        )
        output = Output()

        exit_code = ingress_health.run([], output, ctx)

        # no-tls-ingress should have "No TLS configuration" issue
        no_tls_ingress = next(
            (i for i in output.data["ingresses"] if i["name"] == "no-tls-ingress"),
            None
        )
        assert no_tls_ingress is not None
        assert any("No TLS" in issue for issue in no_tls_ingress["issues"])

    def test_warn_only_filters_healthy(self, mock_context, fixtures_dir):
        """--warn-only only shows ingresses with issues."""
        from scripts.k8s import ingress_health

        ingresses = (fixtures_dir / "k8s" / "ingresses_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "ingress", "-o", "json", "--all-namespaces"): ingresses,
                ("kubectl", "get", "secret", "missing-tls", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "broken-service", "-n", "staging", "-o", "json"): "",
                ("kubectl", "get", "endpoints", "web-service", "-n", "staging", "-o", "json"): "",
            }
        )
        output = Output()

        exit_code = ingress_health.run(["--warn-only"], output, ctx)

        # All returned ingresses should have issues
        for ingress in output.data["ingresses"]:
            assert len(ingress["issues"]) > 0
