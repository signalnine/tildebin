"""Tests for k8s cni_health script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestCniHealth:
    """Tests for cni_health."""

    def test_no_cni_detected(self, capsys):
        """No CNI detected returns exit code 1."""
        from scripts.k8s.cni_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                # No calico pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-kube-controllers",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                # No cilium pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=cilium",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "app.kubernetes.io/name=cilium-agent",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                # No flannel pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-flannel",
                    "-l",
                    "app=flannel",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-flannel",
                    "-l",
                    "k8s-app=flannel",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                # No weave pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "name=weave-net",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                # No AWS CNI pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=aws-node",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                # No Azure CNI pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=azure-cni",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps({"items": []}),
                # Node conditions
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                # No pods with network issues
                (
                    "kubectl",
                    "get",
                    "pods",
                    "--all-namespaces",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "No recognized CNI plugin detected" in captured.out

    def test_healthy_calico(self, capsys):
        """Healthy Calico CNI returns exit code 0."""
        from scripts.k8s.cni_health import run

        calico_pods = {
            "items": [
                {
                    "metadata": {"name": "calico-node-abc", "namespace": "kube-system"},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "calico-node", "ready": True, "restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps(calico_pods),
                # DaemonSet status
                (
                    "kubectl",
                    "get",
                    "daemonset",
                    "calico-node",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "status": {
                            "desiredNumberScheduled": 1,
                            "currentNumberScheduled": 1,
                            "numberReady": 1,
                            "numberAvailable": 1,
                            "numberUnavailable": 0,
                        }
                    }
                ),
                # CNI pods
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                ): json.dumps(calico_pods),
                # Nodes with good network status
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "node-1"},
                                "spec": {"podCIDR": "10.244.0.0/24"},
                                "status": {
                                    "conditions": [
                                        {"type": "NetworkUnavailable", "status": "False"},
                                        {"type": "Ready", "status": "True"},
                                    ]
                                },
                            }
                        ]
                    }
                ),
                # No pods with network issues
                (
                    "kubectl",
                    "get",
                    "pods",
                    "--all-namespaces",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "calico" in captured.out
        assert "OK" in captured.out or "passed" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.cni_health import run

        calico_pods = {
            "items": [
                {
                    "metadata": {"name": "calico-node-abc", "namespace": "kube-system"},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "calico-node", "ready": True, "restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps(calico_pods),
                (
                    "kubectl",
                    "get",
                    "daemonset",
                    "calico-node",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "status": {
                            "desiredNumberScheduled": 1,
                            "currentNumberScheduled": 1,
                            "numberReady": 1,
                            "numberAvailable": 1,
                        }
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                ): json.dumps(calico_pods),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "--all-namespaces",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "detected_plugins" in data
        assert "daemonset_status" in data
        assert "nodes" in data
        assert "issues" in data
        assert "warnings" in data
        assert "healthy" in data

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.cni_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.cni_health import run

        calico_pods = {
            "items": [
                {
                    "metadata": {"name": "calico-node-abc", "namespace": "kube-system"},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "calico-node", "ready": True, "restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps(calico_pods),
                (
                    "kubectl",
                    "get",
                    "daemonset",
                    "calico-node",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "status": {
                            "desiredNumberScheduled": 1,
                            "currentNumberScheduled": 1,
                            "numberReady": 1,
                            "numberAvailable": 1,
                        }
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                ): json.dumps(calico_pods),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "--all-namespaces",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "plugins=" in output.summary
        assert "issues=" in output.summary
        assert "warnings=" in output.summary

    def test_network_unavailable_node(self, capsys):
        """Node with NetworkUnavailable condition triggers issue."""
        from scripts.k8s.cni_health import run

        calico_pods = {
            "items": [
                {
                    "metadata": {"name": "calico-node-abc", "namespace": "kube-system"},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "calico-node", "ready": True, "restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                    "--ignore-not-found",
                ): json.dumps(calico_pods),
                (
                    "kubectl",
                    "get",
                    "daemonset",
                    "calico-node",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "status": {
                            "desiredNumberScheduled": 1,
                            "currentNumberScheduled": 1,
                            "numberReady": 1,
                            "numberAvailable": 1,
                        }
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    "kube-system",
                    "-l",
                    "k8s-app=calico-node",
                    "-o",
                    "json",
                ): json.dumps(calico_pods),
                # Node with NetworkUnavailable=True
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "bad-node"},
                                "spec": {"podCIDR": "10.244.0.0/24"},
                                "status": {
                                    "conditions": [
                                        {"type": "NetworkUnavailable", "status": "True"},
                                    ]
                                },
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "get",
                    "pods",
                    "--all-namespaces",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "NetworkUnavailable" in captured.out
        assert "bad-node" in captured.out
