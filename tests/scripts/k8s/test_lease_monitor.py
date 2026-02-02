"""Tests for k8s lease_monitor script."""

import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_lease(
    name: str,
    namespace: str = "kube-system",
    holder: str = "controller-1",
    renew_age_seconds: int = 5,
    transitions: int = 1,
) -> dict:
    """Create a mock lease for testing."""
    now = datetime.now(timezone.utc)
    renew_time = (now - timedelta(seconds=renew_age_seconds)).isoformat()
    acquire_time = (now - timedelta(hours=1)).isoformat()

    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "spec": {
            "holderIdentity": holder,
            "leaseDurationSeconds": 15,
            "acquireTime": acquire_time,
            "renewTime": renew_time,
            "leaseTransitions": transitions,
        },
    }


class TestLeaseMonitor:
    """Tests for lease_monitor."""

    def test_all_healthy(self, capsys):
        """All healthy leases return exit code 0."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("kube-controller-manager"),
                make_lease("kube-scheduler"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "0 with issues" in captured.out

    def test_stale_lease(self, capsys):
        """Stale lease returns exit code 1."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("kube-controller-manager", renew_age_seconds=120),  # Stale
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "ISSUE" in captured.out or "Stale" in captured.out

    def test_high_transitions(self, capsys):
        """High transition count returns exit code 1."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("controller-1", transitions=15),  # High transitions
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "transition" in captured.out.lower() or "ISSUE" in captured.out

    def test_no_holder(self, capsys):
        """Lease with no holder returns exit code 1."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("orphan-lease", holder=""),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.lease_monitor import run

        leases = {"items": [make_lease("test-lease", namespace="monitoring")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "-n", "monitoring"): json.dumps(leases),
            },
        )
        output = Output()

        result = run(["--namespace", "monitoring"], output, context)

        assert result == 0

    def test_skip_node_leases(self, capsys):
        """Skip node leases flag works."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("node-1", namespace="kube-node-lease"),
                make_lease("kube-controller-manager", namespace="kube-system"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run(["--skip-node-leases"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should only show 1 lease (controller-manager)
        assert "1 leases" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("kube-controller-manager"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "leases" in data
        assert "summary" in data
        assert data["summary"]["total_leases"] == 1

    def test_plain_output(self, capsys):
        """Plain output format works."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("kube-controller-manager"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run(["--format", "plain"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Control Plane" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy leases."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("healthy-lease"),
                make_lease("stale-lease", renew_age_seconds=120),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        captured = capsys.readouterr()
        # Should only show the stale lease
        assert "stale-lease" in captured.out
        assert "1 with issues" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.lease_monitor import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_custom_stale_threshold(self, capsys):
        """Custom stale threshold works."""
        from scripts.k8s.lease_monitor import run

        # Test 1: Lease renewed 10 seconds ago - should be healthy with any reasonable threshold
        leases_fresh = {
            "items": [
                make_lease("controller-1", renew_age_seconds=10),
            ]
        }

        context_fresh = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases_fresh),
            },
        )
        output1 = Output()
        result1 = run(["--stale-threshold", "60"], output1, context_fresh)
        assert result1 == 0  # Fresh lease should be OK

        # Test 2: Lease renewed 300 seconds ago - should be stale with 60s threshold
        leases_stale = {
            "items": [
                make_lease("controller-2", renew_age_seconds=300),
            ]
        }

        context_stale = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases_stale),
            },
        )
        output2 = Output()
        result2 = run(["--stale-threshold", "60"], output2, context_stale)
        assert result2 == 1  # Stale lease should fail

    def test_lease_categorization(self, capsys):
        """Leases are categorized correctly."""
        from scripts.k8s.lease_monitor import run

        # Note: Use "ingress-leader" instead of "ingress-nginx-controller"
        # because "controller" in name matches before "ingress" in categorize_lease()
        leases = {
            "items": [
                make_lease("kube-controller-manager", namespace="kube-system"),
                make_lease("node-1", namespace="kube-node-lease"),
                make_lease("ingress-leader", namespace="ingress-nginx"),
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Check categorization
        types = {lease["lease_type"] for lease in data["leases"]}
        assert "control-plane" in types
        assert "node-heartbeat" in types
        assert "ingress" in types

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.lease_monitor import run

        leases = {
            "items": [
                make_lease("lease-1"),
                make_lease("lease-2", renew_age_seconds=120),  # Stale
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(leases),
            },
        )
        output = Output()

        run([], output, context)

        assert "leases=2" in output.summary
        assert "issues=1" in output.summary
