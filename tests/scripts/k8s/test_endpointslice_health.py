"""Tests for k8s endpointslice_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_endpointslice(
    name: str,
    namespace: str = "default",
    service: str = "my-service",
    ready_count: int = 2,
    not_ready_count: int = 0,
    terminating_count: int = 0,
    ports: int = 1,
) -> dict:
    """Create an EndpointSlice for testing."""
    endpoints = []

    for i in range(ready_count):
        endpoints.append(
            {
                "addresses": [f"10.0.0.{i}"],
                "conditions": {"ready": True, "serving": True, "terminating": False},
            }
        )

    for i in range(not_ready_count):
        endpoints.append(
            {
                "addresses": [f"10.0.1.{i}"],
                "conditions": {"ready": False, "serving": False, "terminating": False},
            }
        )

    for i in range(terminating_count):
        endpoints.append(
            {
                "addresses": [f"10.0.2.{i}"],
                "conditions": {"ready": False, "serving": False, "terminating": True},
            }
        )

    port_list = []
    for i in range(ports):
        port_list.append({"name": f"port-{i}", "port": 8080 + i, "protocol": "TCP"})

    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"kubernetes.io/service-name": service},
        },
        "endpoints": endpoints,
        "ports": port_list,
    }


def make_service(
    name: str,
    namespace: str = "default",
    svc_type: str = "ClusterIP",
    cluster_ip: str = "10.0.0.1",
    selector: dict | None = None,
) -> dict:
    """Create a Service for testing."""
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "type": svc_type,
            "clusterIP": cluster_ip,
            "selector": selector or {"app": name},
        },
    }


class TestEndpointsliceHealth:
    """Tests for endpointslice_health."""

    def test_healthy_endpointslices(self, capsys):
        """Healthy EndpointSlices return exit code 0."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-1-abc", ready_count=3),
                make_endpointslice("svc-2-def", ready_count=2),
            ]
        }
        services = {
            "items": [
                make_service("svc-1"),
                make_service("svc-2"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_unhealthy_no_ready_endpoints(self, capsys):
        """EndpointSlice with no ready endpoints returns exit code 1."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-abc", ready_count=0, not_ready_count=3),
            ]
        }
        services = {"items": [make_service("svc")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[!!]" in captured.out
        assert "No ready endpoints" in captured.out

    def test_high_not_ready_ratio(self, capsys):
        """EndpointSlice with high not-ready ratio is flagged."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-abc", ready_count=1, not_ready_count=3),
            ]
        }
        services = {"items": [make_service("svc")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "not-ready ratio" in captured.out or "not ready" in captured.out

    def test_all_terminating(self, capsys):
        """EndpointSlice with all endpoints terminating is flagged."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-abc", ready_count=0, terminating_count=3),
            ]
        }
        services = {"items": [make_service("svc")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "terminating" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-abc", ready_count=2),
            ]
        }
        services = {"items": [make_service("svc")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "endpointslices" in data
        assert "summary" in data
        assert "missing_services" in data
        assert "fragmented_services" in data

    def test_namespace_filter(self, capsys):
        """Namespace filter works correctly."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-abc", namespace="production", ready_count=2),
            ]
        }
        services = {"items": [make_service("svc", namespace="production")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "-n", "production"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "-n", "production"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "production" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy EndpointSlices."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("healthy-svc-abc", ready_count=3),
                make_endpointslice("unhealthy-svc-def", ready_count=0, not_ready_count=2),
            ]
        }
        services = {"items": []}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "unhealthy-svc-def" in captured.out
        # Healthy one should be filtered
        assert "healthy-svc-abc" not in captured.out or "[OK]" not in captured.out.split("healthy-svc-abc")[0]

    def test_missing_services_detected(self, capsys):
        """Services without EndpointSlices are detected."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {"items": []}  # No endpointslices
        services = {
            "items": [
                make_service("orphan-service", selector={"app": "orphan"}),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Missing EndpointSlices" in captured.out
        assert "orphan-service" in captured.out

    def test_skip_coverage_check(self, capsys):
        """--skip-coverage-check skips service coverage check."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {"items": [make_endpointslice("svc-abc", ready_count=2)]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
            },
        )
        output = Output()

        result = run(["--skip-coverage-check"], output, context)

        assert result == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.endpointslice_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_no_ports_warning(self, capsys):
        """EndpointSlice with no ports is flagged."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-abc", ready_count=2, ports=0),
            ]
        }
        services = {"items": []}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "No ports defined" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.endpointslice_health import run

        endpointslices = {
            "items": [
                make_endpointslice("svc-abc", ready_count=2),
            ]
        }
        services = {"items": []}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    endpointslices
                ),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps(
                    services
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "slices=" in output.summary
        assert "healthy=" in output.summary
