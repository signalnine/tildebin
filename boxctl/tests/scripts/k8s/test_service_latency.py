"""Tests for service_latency script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def latency_services(fixtures_dir):
    """Load services fixture."""
    return (fixtures_dir / "k8s" / "latency_services.json").read_text()


@pytest.fixture
def latency_endpoints(fixtures_dir):
    """Load endpoints fixture."""
    return (fixtures_dir / "k8s" / "latency_endpoints.json").read_text()


@pytest.fixture
def latency_endpoint_web(fixtures_dir):
    """Load single web-service endpoint fixture."""
    return (fixtures_dir / "k8s" / "latency_endpoint_web.json").read_text()


class TestServiceLatency:
    """Tests for service_latency script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import service_latency

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = service_latency.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_healthy_services(self, mock_context, latency_services, latency_endpoint_web):
        """Returns 0 when all services have healthy endpoints."""
        from scripts.k8s import service_latency

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): latency_services,
                ("kubectl", "get", "endpoints", "web-service", "-n", "production",
                 "-o", "json"): latency_endpoint_web,
            }
        )
        output = Output()

        exit_code = service_latency.run([], output, ctx)

        assert exit_code == 0
        assert output.data["has_issues"] is False
        # Should have checked at least the web-service
        assert output.data["summary"]["healthy"] >= 1

    def test_no_services_found(self, mock_context):
        """Handles case when no services match criteria."""
        from scripts.k8s import service_latency

        empty_services = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): empty_services,
            }
        )
        output = Output()

        exit_code = service_latency.run([], output, ctx)

        assert exit_code == 0
        assert len(output.warnings) > 0
        assert output.data["has_issues"] is False

    def test_service_no_endpoints_critical(self, mock_context):
        """Detects services with no endpoints."""
        from scripts.k8s import service_latency

        service = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "production"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.1.100",
                    "ports": [{"name": "http", "port": 80, "protocol": "TCP"}]
                }
            }]
        })

        empty_endpoints = json.dumps({"subsets": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): service,
                ("kubectl", "get", "endpoints", "web-service", "-n", "production",
                 "-o", "json"): empty_endpoints,
            }
        )
        output = Output()

        exit_code = service_latency.run([], output, ctx)

        assert exit_code == 1
        assert output.data["has_issues"] is True
        assert output.data["summary"]["critical"] >= 1
        critical_svc = [s for s in output.data["services"] if s.get("status") == "critical"]
        assert any("No ready endpoints" in s.get("issues", []) for s in critical_svc)

    def test_skips_headless_services(self, mock_context, latency_services, latency_endpoint_web):
        """Skips headless services correctly."""
        from scripts.k8s import service_latency

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): latency_services,
                ("kubectl", "get", "endpoints", "web-service", "-n", "production",
                 "-o", "json"): latency_endpoint_web,
            }
        )
        output = Output()

        exit_code = service_latency.run([], output, ctx)

        skipped = [s for s in output.data["services"] if s.get("status") == "skipped"]
        # headless-service and external-service should be skipped
        assert len(skipped) >= 2
        assert any(s.get("type") == "headless" for s in skipped)
        assert any(s.get("type") == "ExternalName" for s in skipped)

    def test_specific_namespace(self, mock_context):
        """Can check specific namespace."""
        from scripts.k8s import service_latency

        service = json.dumps({
            "items": [{
                "metadata": {"name": "api-service", "namespace": "staging"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.2.100",
                    "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]
                }
            }]
        })

        endpoints = json.dumps({
            "subsets": [{
                "addresses": [{"ip": "10.244.2.20"}],
                "ports": [{"port": 8080}]
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "-n", "staging"): service,
                ("kubectl", "get", "endpoints", "api-service", "-n", "staging",
                 "-o", "json"): endpoints,
            }
        )
        output = Output()

        exit_code = service_latency.run(["-n", "staging"], output, ctx)

        assert exit_code == 0
        assert any("-n" in cmd and "staging" in cmd for cmd in ctx.commands_run)

    def test_label_selector(self, mock_context):
        """Can filter by label selector."""
        from scripts.k8s import service_latency

        service = json.dumps({
            "items": [{
                "metadata": {"name": "nginx-service", "namespace": "production"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.3.100",
                    "ports": [{"port": 80}]
                }
            }]
        })

        endpoints = json.dumps({
            "subsets": [{
                "addresses": [{"ip": "10.244.3.30"}],
                "ports": [{"port": 80}]
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces", "-l", "app=nginx"): service,
                ("kubectl", "get", "endpoints", "nginx-service", "-n", "production",
                 "-o", "json"): endpoints,
            }
        )
        output = Output()

        exit_code = service_latency.run(["-l", "app=nginx"], output, ctx)

        assert exit_code == 0
        assert any("-l" in cmd and "app=nginx" in cmd for cmd in ctx.commands_run)

    def test_include_system_namespaces(self, mock_context):
        """--include-system includes system namespaces."""
        from scripts.k8s import service_latency

        system_service = json.dumps({
            "items": [{
                "metadata": {"name": "kube-dns", "namespace": "kube-system"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.0.10",
                    "ports": [{"port": 53}]
                }
            }]
        })

        endpoints = json.dumps({
            "subsets": [{
                "addresses": [{"ip": "10.244.0.5"}],
                "ports": [{"port": 53}]
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): system_service,
                ("kubectl", "get", "endpoints", "kube-dns", "-n", "kube-system",
                 "-o", "json"): endpoints,
            }
        )
        output = Output()

        exit_code = service_latency.run(["--include-system"], output, ctx)

        assert exit_code == 0
        # kube-dns should be checked when --include-system is used
        assert output.data["summary"]["total_checked"] >= 1
        checked = [s for s in output.data["services"] if s.get("status") != "skipped"]
        assert any(s.get("namespace") == "kube-system" for s in checked)
