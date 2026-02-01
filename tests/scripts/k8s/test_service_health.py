"""Tests for service_health script."""

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


class TestServiceHealth:
    """Tests for service_health script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import service_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = service_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_services_healthy(
        self, mock_context, svc_services_healthy, svc_endpoints_healthy
    ):
        """Returns 0 when all services have healthy endpoints."""
        from scripts.k8s import service_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): svc_services_healthy,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): svc_endpoints_healthy,
            }
        )
        output = Output()

        exit_code = service_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_issues"] == 0

    def test_detects_no_endpoints(self, mock_context, svc_endpoints_none):
        """Detects services with no endpoints."""
        from scripts.k8s import service_health

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
            }
        )
        output = Output()

        exit_code = service_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["errors"] >= 1
        assert any(
            i["issue"] == "No endpoints available (no backing pods)"
            for i in output.data["issues"]
        )

    def test_detects_all_not_ready(self, mock_context, svc_endpoints_not_ready):
        """Detects services where all endpoints are NotReady."""
        from scripts.k8s import service_health

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
            }
        )
        output = Output()

        exit_code = service_health.run([], output, ctx)

        assert exit_code == 1
        assert any(
            i["issue"] == "All endpoints not ready"
            for i in output.data["issues"]
        )

    def test_detects_partial_not_ready(self, mock_context):
        """Detects services with some endpoints not ready."""
        from scripts.k8s import service_health

        service = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "production"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.1.100"
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
            }
        )
        output = Output()

        exit_code = service_health.run([], output, ctx)

        assert exit_code == 1
        assert any(
            i["issue"] == "Some endpoints not ready"
            for i in output.data["issues"]
        )
        assert output.data["summary"]["warnings"] >= 1

    def test_skips_headless_services(self, mock_context):
        """Skips headless services (no ClusterIP)."""
        from scripts.k8s import service_health

        headless_service = json.dumps({
            "items": [{
                "metadata": {"name": "headless-svc", "namespace": "production"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "None"
                }
            }]
        })

        empty_endpoints = json.dumps({"items": []})

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): headless_service,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): empty_endpoints,
            }
        )
        output = Output()

        exit_code = service_health.run([], output, ctx)

        # No issues because headless services are skipped
        assert exit_code == 0
        assert output.data["summary"]["total_issues"] == 0

    def test_verbose_shows_healthy_services(self, mock_context, svc_services_healthy, svc_endpoints_healthy):
        """--verbose shows healthy services."""
        from scripts.k8s import service_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "--all-namespaces"): svc_services_healthy,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "--all-namespaces"): svc_endpoints_healthy,
            }
        )
        output = Output()

        exit_code = service_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "healthy_services" in output.data
        assert len(output.data["healthy_services"]) > 0

    def test_specific_namespace(self, mock_context):
        """Can check specific namespace."""
        from scripts.k8s import service_health

        service = json.dumps({
            "items": [{
                "metadata": {"name": "web-service", "namespace": "staging"},
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.96.1.100"
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

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "services", "-o", "json",
                 "-n", "staging"): service,
                ("kubectl", "get", "endpoints", "-o", "json",
                 "-n", "staging"): endpoints,
            }
        )
        output = Output()

        exit_code = service_health.run(["-n", "staging"], output, ctx)

        assert exit_code == 0
        assert any("-n" in cmd and "staging" in cmd for cmd in ctx.commands_run)
