"""Tests for service_endpoint script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def svc_services_healthy(fixtures_dir):
    """Load healthy services fixture."""
    return (fixtures_dir / "k8s" / "svc_services_healthy.json").read_text()


@pytest.fixture
def svc_endpoints_healthy(fixtures_dir):
    """Load healthy endpoints fixture."""
    return (fixtures_dir / "k8s" / "svc_endpoints_healthy.json").read_text()


@pytest.fixture
def svc_endpoints_none(fixtures_dir):
    """Load empty endpoints fixture."""
    return (fixtures_dir / "k8s" / "svc_endpoints_none.json").read_text()


@pytest.fixture
def svc_endpoints_not_ready(fixtures_dir):
    """Load not-ready endpoints fixture."""
    return (fixtures_dir / "k8s" / "svc_endpoints_not_ready.json").read_text()


@pytest.fixture
def svc_pods(fixtures_dir):
    """Load pods fixture."""
    return (fixtures_dir / "k8s" / "svc_pods.json").read_text()


class TestServiceEndpoint:
    """Tests for service_endpoint script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import service_endpoint

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = service_endpoint.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_services_healthy(
        self, mock_context, svc_services_healthy, svc_endpoints_healthy, svc_pods
    ):
        """Returns 0 when all services have healthy endpoints."""
        from scripts.k8s import service_endpoint

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): svc_services_healthy,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): svc_endpoints_healthy,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): svc_pods,
            }
        )
        output = Output()

        exit_code = service_endpoint.run([], output, ctx)

        assert exit_code == 0
        assert output.data["total_issues"] == 0
        assert output.data["services_checked"] == 2

    def test_detects_no_endpoints(
        self, mock_context, svc_services_healthy, svc_endpoints_none, svc_pods
    ):
        """Detects services with no endpoints."""
        from scripts.k8s import service_endpoint

        # Single service for simpler test
        single_service = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "production"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.1.100",
                    "selector": {"app": "web"}
                }
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): single_service,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): svc_endpoints_none,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): svc_pods,
            }
        )
        output = Output()

        exit_code = service_endpoint.run([], output, ctx)

        assert exit_code == 1
        assert output.data["critical"] >= 1
        # Pods exist but no endpoints
        critical = [i for i in output.data["issues"] if i["severity"] == "critical"]
        assert len(critical) > 0

    def test_detects_all_endpoints_not_ready(
        self, mock_context, svc_endpoints_not_ready, svc_pods
    ):
        """Detects services where all endpoints are NotReady."""
        from scripts.k8s import service_endpoint

        single_service = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "production"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.1.100",
                    "selector": {"app": "web"}
                }
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): single_service,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): svc_endpoints_not_ready,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): svc_pods,
            }
        )
        output = Output()

        exit_code = service_endpoint.run([], output, ctx)

        assert exit_code == 1
        assert any(
            i["issue"] == "all_endpoints_not_ready"
            for i in output.data["issues"]
        )

    def test_detects_loadbalancer_no_ip(self, mock_context, svc_endpoints_healthy, svc_pods):
        """Detects LoadBalancer services without external IP."""
        from scripts.k8s import service_endpoint

        lb_service_no_ip = json.dumps({
            "items": [{
                "metadata": {"name": "api-service", "namespace": "production"},
                "spec": {
                    "type": "LoadBalancer",
                    "clusterIP": "10.96.1.101",
                    "selector": {"app": "api"}
                },
                "status": {
                    "loadBalancer": {}
                }
            }]
        })

        endpoints = json.dumps({
            "items": [{
                "metadata": {"name": "api-service", "namespace": "production"},
                "subsets": [{
                    "addresses": [{"ip": "10.244.2.20"}],
                    "ports": [{"port": 8443}]
                }]
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): lb_service_no_ip,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): endpoints,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): svc_pods,
            }
        )
        output = Output()

        exit_code = service_endpoint.run([], output, ctx)

        # This is a warning, not critical
        assert any(
            i["issue"] == "loadbalancer_no_external_ip"
            for i in output.data["issues"]
        )

    def test_detects_partial_endpoints_not_ready(self, mock_context, svc_pods):
        """Detects services with some endpoints not ready."""
        from scripts.k8s import service_endpoint

        service = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "production"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.1.100",
                    "selector": {"app": "web"}
                }
            }]
        })

        partial_endpoints = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "production"},
                "subsets": [{
                    "addresses": [{"ip": "10.244.1.10"}],
                    "notReadyAddresses": [{"ip": "10.244.1.11"}],
                    "ports": [{"port": 8080}]
                }]
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): service,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): partial_endpoints,
                ("kubectl", "get", "pods", "-o", "json",
                 "--all-namespaces"): svc_pods,
            }
        )
        output = Output()

        exit_code = service_endpoint.run([], output, ctx)

        assert exit_code == 1
        assert any(
            i["issue"] == "partial_endpoints_not_ready"
            for i in output.data["issues"]
        )
        assert output.data["warnings"] >= 1

    def test_specific_namespace(self, mock_context):
        """Can check specific namespace."""
        from scripts.k8s import service_endpoint

        service = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "staging"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.1.100",
                    "selector": {"app": "web"}
                }
            }]
        })

        endpoints = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "staging"},
                "subsets": [{
                    "addresses": [{"ip": "10.244.1.10"}],
                    "ports": [{"port": 8080}]
                }]
            }]
        })

        pods = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "-n", "staging"): service,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "-n", "staging"): endpoints,
                ("kubectl", "get", "pods", "-o", "json",
                 "-n", "staging"): pods,
            }
        )
        output = Output()

        exit_code = service_endpoint.run(["-n", "staging"], output, ctx)

        assert exit_code == 0
        # Verify namespace was used in commands
        assert any("-n" in cmd and "staging" in cmd for cmd in ctx.commands_run)
