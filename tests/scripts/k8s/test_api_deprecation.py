"""Tests for k8s api_deprecation script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestApiDeprecation:
    """Tests for api_deprecation."""

    def test_no_deprecated_apis(self, capsys):
        """No deprecated APIs returns exit code 0."""
        from scripts.k8s.api_deprecation import run

        # Mock cluster version and empty resources
        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(
                    {
                        "serverVersion": {"major": "1", "minor": "28"},
                    }
                ),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "poddisruptionbudgets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "horizontalpodautoscalers", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterroles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterrolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "customresourcedefinitions", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csidriver", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csinodes", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "storageclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "volumeattachments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "certificatesigningrequests", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "flowschemas", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "prioritylevelconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "runtimeclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "priorityclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No deprecated APIs found" in captured.out

    def test_deprecated_api_found(self, capsys):
        """Deprecated API returns exit code 1."""
        from scripts.k8s.api_deprecation import run

        # Mock with a deprecated ingress
        deprecated_ingress = {
            "items": [
                {
                    "apiVersion": "extensions/v1beta1",
                    "kind": "Ingress",
                    "metadata": {"name": "old-ingress", "namespace": "default"},
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(
                    {
                        "serverVersion": {"major": "1", "minor": "20"},
                    }
                ),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps(
                    deprecated_ingress
                ),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "poddisruptionbudgets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "horizontalpodautoscalers", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterroles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterrolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "customresourcedefinitions", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csidriver", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csinodes", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "storageclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "volumeattachments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "certificatesigningrequests", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "flowschemas", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "prioritylevelconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "runtimeclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "priorityclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "old-ingress" in captured.out
        assert "WARNING" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.api_deprecation import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(
                    {
                        "serverVersion": {"major": "1", "minor": "28"},
                    }
                ),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "poddisruptionbudgets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "horizontalpodautoscalers", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterroles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterrolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "customresourcedefinitions", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csidriver", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csinodes", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "storageclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "volumeattachments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "certificatesigningrequests", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "flowschemas", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "prioritylevelconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "runtimeclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "priorityclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "cluster_version" in data
        assert "summary" in data
        assert "critical" in data
        assert "warning" in data
        assert "info" in data
        assert "healthy" in data

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.api_deprecation import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.api_deprecation import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(
                    {
                        "serverVersion": {"major": "1", "minor": "28"},
                    }
                ),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "poddisruptionbudgets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "horizontalpodautoscalers", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterroles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterrolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "customresourcedefinitions", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csidriver", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csinodes", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "storageclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "volumeattachments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "certificatesigningrequests", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "flowschemas", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "prioritylevelconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "runtimeclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "priorityclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "critical=" in output.summary
        assert "warning=" in output.summary
        assert "info=" in output.summary

    def test_target_version_check(self, capsys):
        """Target version triggers critical for deprecated APIs."""
        from scripts.k8s.api_deprecation import run

        # Mock with a deprecated ingress on v1.20, targeting v1.22
        deprecated_ingress = {
            "items": [
                {
                    "apiVersion": "extensions/v1beta1",
                    "kind": "Ingress",
                    "metadata": {"name": "old-ingress", "namespace": "default"},
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(
                    {
                        "serverVersion": {"major": "1", "minor": "20"},
                    }
                ),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "daemonsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "ingresses", "-o", "json", "--all-namespaces"): json.dumps(
                    deprecated_ingress
                ),
                ("kubectl", "get", "networkpolicies", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "poddisruptionbudgets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "horizontalpodautoscalers", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterroles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "clusterrolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "roles", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "rolebindings", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "customresourcedefinitions", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csidriver", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "csinodes", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "storageclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "volumeattachments", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "certificatesigningrequests", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "leases", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "endpointslices", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "flowschemas", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "prioritylevelconfigurations", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "runtimeclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "priorityclasses", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--target-version", "1.22"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "blocking upgrade" in captured.out
