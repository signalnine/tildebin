"""Tests for dns_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def dns_pods_healthy(fixtures_dir):
    """Load healthy DNS pods fixture."""
    return (fixtures_dir / "k8s" / "dns_pods_healthy.json").read_text()


@pytest.fixture
def dns_pods_not_ready(fixtures_dir):
    """Load not-ready DNS pods fixture."""
    return (fixtures_dir / "k8s" / "dns_pods_not_ready.json").read_text()


@pytest.fixture
def dns_service(fixtures_dir):
    """Load DNS service fixture."""
    return (fixtures_dir / "k8s" / "dns_service.json").read_text()


@pytest.fixture
def dns_endpoints_healthy(fixtures_dir):
    """Load healthy DNS endpoints fixture."""
    return (fixtures_dir / "k8s" / "dns_endpoints_healthy.json").read_text()


@pytest.fixture
def dns_endpoints_none(fixtures_dir):
    """Load empty DNS endpoints fixture."""
    return (fixtures_dir / "k8s" / "dns_endpoints_none.json").read_text()


class TestDnsHealth:
    """Tests for dns_health script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import dns_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = dns_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_dns_healthy(
        self, mock_context, dns_pods_healthy, dns_service, dns_endpoints_healthy
    ):
        """Returns 0 when all DNS components are healthy."""
        from scripts.k8s import dns_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-n", "kube-system",
                 "-l", "k8s-app=kube-dns", "-o", "json"): dns_pods_healthy,
                ("kubectl", "get", "service", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_service,
                ("kubectl", "get", "endpoints", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_endpoints_healthy,
            }
        )
        output = Output()

        exit_code = dns_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["healthy"] is True
        assert len(output.data["pods"]) == 2
        assert all(p["ready"] for p in output.data["pods"])
        assert output.data["endpoints"]["ready"] == 2

    def test_dns_pods_not_ready(
        self, mock_context, dns_pods_not_ready, dns_service, dns_endpoints_healthy
    ):
        """Returns 1 when DNS pods are not ready."""
        from scripts.k8s import dns_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-n", "kube-system",
                 "-l", "k8s-app=kube-dns", "-o", "json"): dns_pods_not_ready,
                ("kubectl", "get", "service", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_service,
                ("kubectl", "get", "endpoints", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_endpoints_healthy,
            }
        )
        output = Output()

        exit_code = dns_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["healthy"] is False
        assert len(output.data["issues"]) > 0
        assert any("not ready" in issue.lower() for issue in output.data["issues"])

    def test_no_dns_endpoints(
        self, mock_context, dns_pods_healthy, dns_service, dns_endpoints_none
    ):
        """Returns 1 when DNS has no ready endpoints."""
        from scripts.k8s import dns_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-n", "kube-system",
                 "-l", "k8s-app=kube-dns", "-o", "json"): dns_pods_healthy,
                ("kubectl", "get", "service", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_service,
                ("kubectl", "get", "endpoints", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_endpoints_none,
            }
        )
        output = Output()

        exit_code = dns_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["healthy"] is False
        assert any("endpoint" in issue.lower() for issue in output.data["issues"])

    def test_custom_namespace(
        self, mock_context, dns_pods_healthy, dns_service, dns_endpoints_healthy
    ):
        """Can specify custom namespace for DNS."""
        from scripts.k8s import dns_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-n", "custom-dns",
                 "-l", "k8s-app=kube-dns", "-o", "json"): dns_pods_healthy,
                ("kubectl", "get", "service", "kube-dns", "-n", "custom-dns",
                 "-o", "json"): dns_service,
                ("kubectl", "get", "endpoints", "kube-dns", "-n", "custom-dns",
                 "-o", "json"): dns_endpoints_healthy,
            }
        )
        output = Output()

        exit_code = dns_health.run(["-n", "custom-dns"], output, ctx)

        assert exit_code == 0
        # Verify custom namespace was used
        assert any("custom-dns" in " ".join(cmd) for cmd in ctx.commands_run)

    def test_high_restart_count_warning(self, mock_context, dns_service, dns_endpoints_healthy):
        """Warns when pods have high restart count."""
        from scripts.k8s import dns_health

        high_restart_pods = json.dumps({
            "apiVersion": "v1",
            "items": [{
                "metadata": {"name": "coredns-abc123", "namespace": "kube-system"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{
                        "name": "coredns",
                        "ready": True,
                        "restartCount": 12
                    }]
                }
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-n", "kube-system",
                 "-l", "k8s-app=kube-dns", "-o", "json"): high_restart_pods,
                ("kubectl", "get", "service", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_service,
                ("kubectl", "get", "endpoints", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_endpoints_healthy,
            }
        )
        output = Output()

        exit_code = dns_health.run([], output, ctx)

        # Should return 0 (healthy) but have warnings
        assert exit_code == 0
        assert len(output.data["warnings"]) > 0
        assert any("restart" in w.lower() for w in output.data["warnings"])

    def test_single_pod_ha_warning(self, mock_context, dns_service, dns_endpoints_healthy):
        """Warns when only one DNS pod is ready (HA concern)."""
        from scripts.k8s import dns_health

        single_pod = json.dumps({
            "apiVersion": "v1",
            "items": [{
                "metadata": {"name": "coredns-abc123", "namespace": "kube-system"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{
                        "name": "coredns",
                        "ready": True,
                        "restartCount": 0
                    }]
                }
            }]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-n", "kube-system",
                 "-l", "k8s-app=kube-dns", "-o", "json"): single_pod,
                ("kubectl", "get", "service", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_service,
                ("kubectl", "get", "endpoints", "kube-dns", "-n", "kube-system",
                 "-o", "json"): dns_endpoints_healthy,
            }
        )
        output = Output()

        exit_code = dns_health.run([], output, ctx)

        assert exit_code == 0
        assert any("HA" in w or "scaling" in w.lower() for w in output.data["warnings"])
