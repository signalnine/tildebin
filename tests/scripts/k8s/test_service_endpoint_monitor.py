"""Tests for service_endpoint_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


class TestServiceEndpointMonitor:
    """Tests for service_endpoint_monitor script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import service_endpoint_monitor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = service_endpoint_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_services_healthy(self, mock_context, fixtures_dir):
        """Returns 0 when all services have healthy endpoints."""
        from scripts.k8s import service_endpoint_monitor

        services = (fixtures_dir / "k8s" / "services_healthy.json").read_text()
        endpoints = (fixtures_dir / "k8s" / "endpoints_healthy.json").read_text()
        pods = (fixtures_dir / "k8s" / "pods_for_services.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): services,
                ("kubectl", "get", "endpoints", "-o", "json", "--all-namespaces"): endpoints,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = service_endpoint_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["critical"] == 0

    def test_services_with_issues(self, mock_context, fixtures_dir):
        """Returns 1 when services have endpoint issues."""
        from scripts.k8s import service_endpoint_monitor

        services = (fixtures_dir / "k8s" / "services_issues.json").read_text()
        endpoints = (fixtures_dir / "k8s" / "endpoints_issues.json").read_text()
        pods = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): services,
                ("kubectl", "get", "endpoints", "-o", "json", "--all-namespaces"): endpoints,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = service_endpoint_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["total_issues"] > 0

    def test_detects_no_matching_pods(self, mock_context, fixtures_dir):
        """Detects services with no matching pods."""
        from scripts.k8s import service_endpoint_monitor

        services = (fixtures_dir / "k8s" / "services_issues.json").read_text()
        endpoints = (fixtures_dir / "k8s" / "endpoints_issues.json").read_text()
        pods = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): services,
                ("kubectl", "get", "endpoints", "-o", "json", "--all-namespaces"): endpoints,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = service_endpoint_monitor.run([], output, ctx)

        # Should detect "no_matching_pods" issue
        issues = output.data["issues"]
        issue_types = [i["issue"] for i in issues]
        assert "no_matching_pods" in issue_types or "all_endpoints_not_ready" in issue_types

    def test_detects_loadbalancer_no_ip(self, mock_context, fixtures_dir):
        """Detects LoadBalancer services without external IPs."""
        from scripts.k8s import service_endpoint_monitor

        services = (fixtures_dir / "k8s" / "services_issues.json").read_text()
        endpoints = (fixtures_dir / "k8s" / "endpoints_issues.json").read_text()
        pods = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): services,
                ("kubectl", "get", "endpoints", "-o", "json", "--all-namespaces"): endpoints,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        output = Output()

        exit_code = service_endpoint_monitor.run([], output, ctx)

        issues = output.data["issues"]
        issue_types = [i["issue"] for i in issues]
        assert "loadbalancer_no_external_ip" in issue_types

    def test_namespace_filter(self, mock_context):
        """Filters by namespace when specified."""
        from scripts.k8s import service_endpoint_monitor

        empty_list = '{"apiVersion": "v1", "kind": "List", "items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json", "-n", "production"): empty_list,
                ("kubectl", "get", "endpoints", "-o", "json", "-n", "production"): empty_list,
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): empty_list,
            }
        )
        output = Output()

        exit_code = service_endpoint_monitor.run(["-n", "production"], output, ctx)

        assert exit_code == 0
