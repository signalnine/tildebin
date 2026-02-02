"""Tests for k8s finalizer_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_namespace(
    name: str,
    phase: str = "Active",
    finalizers: list | None = None,
    deletion_timestamp: str | None = None,
) -> dict:
    """Create a Namespace for testing."""
    ns = {
        "metadata": {"name": name},
        "status": {"phase": phase, "conditions": []},
    }
    if finalizers:
        ns["metadata"]["finalizers"] = finalizers
    if deletion_timestamp:
        ns["metadata"]["deletionTimestamp"] = deletion_timestamp
    return ns


def make_resource(
    name: str,
    kind: str = "Pod",
    namespace: str = "default",
    finalizers: list | None = None,
    deletion_timestamp: str | None = None,
) -> dict:
    """Create a resource for testing."""
    res = {
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace},
    }
    if finalizers:
        res["metadata"]["finalizers"] = finalizers
    if deletion_timestamp:
        res["metadata"]["deletionTimestamp"] = deletion_timestamp
    return res


def make_pv(
    name: str,
    finalizers: list | None = None,
    deletion_timestamp: str | None = None,
    phase: str = "Bound",
) -> dict:
    """Create a PersistentVolume for testing."""
    pv = {
        "kind": "PersistentVolume",
        "metadata": {"name": name},
        "status": {"phase": phase},
    }
    if finalizers:
        pv["metadata"]["finalizers"] = finalizers
    if deletion_timestamp:
        pv["metadata"]["deletionTimestamp"] = deletion_timestamp
    return pv


class TestFinalizerAnalyzer:
    """Tests for finalizer_analyzer."""

    def test_no_stuck_resources(self, capsys):
        """No stuck resources returns exit code 0."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {"items": [make_namespace("default")]}
        pods = {"items": [make_resource("pod-1", kind="Pod")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "persistentvolumeclaims", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "pv", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No resources stuck" in captured.out

    def test_terminating_namespace_detected(self, capsys):
        """Terminating namespace with finalizers returns exit code 1."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {
            "items": [
                make_namespace(
                    "stuck-ns",
                    phase="Terminating",
                    finalizers=["kubernetes.io/finalizer"],
                    deletion_timestamp="2024-01-01T00:00:00Z",
                )
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "persistentvolumeclaims", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "pv", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "stuck-ns" in captured.out
        assert "Terminating Namespaces" in captured.out

    def test_stuck_resource_detected(self, capsys):
        """Resource with finalizer and deletionTimestamp is detected."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {"items": [make_namespace("default")]}
        pods = {
            "items": [
                make_resource(
                    "stuck-pod",
                    kind="Pod",
                    finalizers=["kubernetes.io/pvc-protection"],
                    deletion_timestamp="2024-01-01T00:00:00Z",
                )
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "persistentvolumeclaims", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "pv", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "stuck-pod" in captured.out
        assert "Stuck in Terminating" in captured.out

    def test_stuck_pv_detected(self, capsys):
        """PV with finalizer and deletionTimestamp is detected."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {"items": [make_namespace("default")]}
        pvs = {
            "items": [
                make_pv(
                    "stuck-pv",
                    finalizers=["kubernetes.io/pv-protection"],
                    deletion_timestamp="2024-01-01T00:00:00Z",
                )
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "persistentvolumeclaims", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "pv", "-o", "json"): json.dumps(pvs),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "stuck-pv" in captured.out
        assert "PersistentVolumes" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {"items": [make_namespace("default")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "persistentvolumeclaims", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "pv", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "terminating_namespaces" in data
        assert "stuck_resources" in data
        assert "stuck_persistent_volumes" in data
        assert "summary" in data

    def test_namespaces_only(self, capsys):
        """--namespaces-only only checks namespaces."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {"items": [make_namespace("default")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
            },
        )
        output = Output()

        result = run(["--namespaces-only"], output, context)

        assert result == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.finalizer_analyzer import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format includes header."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {
            "items": [
                make_namespace(
                    "stuck-ns",
                    phase="Terminating",
                    finalizers=["kubernetes.io/finalizer"],
                    deletion_timestamp="2024-01-01T00:00:00Z",
                )
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "persistentvolumeclaims", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "pv", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "TYPE" in captured.out
        assert "NAME" in captured.out
        assert "FINALIZERS" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.finalizer_analyzer import run

        namespaces = {"items": [make_namespace("default")]}

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): json.dumps(namespaces),
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "services", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "configmaps", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "persistentvolumeclaims", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "serviceaccounts", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "pv", "-o", "json"): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "namespaces=" in output.summary
        assert "resources=" in output.summary
        assert "pvs=" in output.summary
