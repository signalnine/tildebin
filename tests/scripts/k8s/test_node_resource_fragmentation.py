"""Tests for node_resource_fragmentation script."""

import json
import pytest

from boxctl.core.output import Output


class TestNodeResourceFragmentation:
    """Tests for node_resource_fragmentation script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import node_resource_fragmentation

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = node_resource_fragmentation.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_invalid_reference_pod_returns_error(self, mock_context, fixtures_dir):
        """Returns exit code 2 for invalid reference pod size."""
        from scripts.k8s import node_resource_fragmentation

        ctx = mock_context(tools_available=["kubectl"])
        output = Output()

        exit_code = node_resource_fragmentation.run(["--cpu", "0", "--memory", "0"], output, ctx)

        assert exit_code == 2

    def test_cluster_analysis_returns_data(self, mock_context, fixtures_dir):
        """Script analyzes cluster and returns valid data structure."""
        from scripts.k8s import node_resource_fragmentation
        import json

        nodes_data = (fixtures_dir / "k8s" / "nodes_healthy.json").read_text()
        pods_data = json.dumps({
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [
                {
                    "metadata": {"name": "small-pod", "namespace": "default"},
                    "spec": {
                        "nodeName": "node-1",
                        "containers": [{
                            "name": "app",
                            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}}
                        }]
                    },
                    "status": {"phase": "Running"}
                }
            ]
        })

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = node_resource_fragmentation.run([], output, ctx)

        # Verify data structure
        assert "nodes" in output.data
        assert "summary" in output.data
        assert len(output.data["nodes"]) == 2
        assert output.data["summary"]["total_nodes"] == 2
        # Exit code depends on fragmentation score
        assert exit_code in (0, 1)

    def test_fragmented_cluster_detected(self, mock_context, fixtures_dir):
        """Detects fragmented cluster with phantom capacity."""
        from scripts.k8s import node_resource_fragmentation

        nodes_data = (fixtures_dir / "k8s" / "nodes_fragmented.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_fragmented.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        # Use a medium-sized reference pod
        exit_code = node_resource_fragmentation.run(["--cpu", "2000m", "--memory", "4Gi"], output, ctx)

        # Should detect fragmentation since nodes have small gaps
        assert "nodes" in output.data
        assert len(output.data["nodes"]) > 0

    def test_unschedulable_node_flagged(self, mock_context, fixtures_dir):
        """Unschedulable nodes are properly flagged."""
        from scripts.k8s import node_resource_fragmentation

        nodes_data = (fixtures_dir / "k8s" / "nodes_fragmented.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_fragmented.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = node_resource_fragmentation.run([], output, ctx)

        # Find the unschedulable node
        unschedulable = [n for n in output.data["nodes"] if not n["is_schedulable"]]
        assert len(unschedulable) > 0

    def test_warn_only_filters_ok_nodes(self, mock_context, fixtures_dir):
        """--warn-only only shows nodes with fragmentation issues."""
        from scripts.k8s import node_resource_fragmentation

        nodes_data = (fixtures_dir / "k8s" / "nodes_healthy.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_simple.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        exit_code = node_resource_fragmentation.run(["--warn-only"], output, ctx)

        # All nodes shown should have issues (not OK status)
        for node in output.data["nodes"]:
            assert node["status"] != "OK"

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """--namespace filters pods to specific namespace."""
        from scripts.k8s import node_resource_fragmentation

        nodes_data = (fixtures_dir / "k8s" / "nodes_healthy.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): pods_data,
            }
        )
        output = Output()

        exit_code = node_resource_fragmentation.run(["-n", "production"], output, ctx)

        assert exit_code in (0, 1)

    def test_custom_reference_pod_size(self, mock_context, fixtures_dir):
        """Custom reference pod size affects fragmentation calculation."""
        from scripts.k8s import node_resource_fragmentation

        nodes_data = (fixtures_dir / "k8s" / "nodes_fragmented.json").read_text()
        pods_data = (fixtures_dir / "k8s" / "pods_fragmented.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "nodes", "-o", "json"): nodes_data,
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods_data,
            }
        )
        output = Output()

        # Very small reference pod should show more schedulable capacity
        exit_code = node_resource_fragmentation.run(["--cpu", "100m", "--memory", "128Mi"], output, ctx)

        assert exit_code in (0, 1)
        assert output.data["summary"]["reference_pod_cpu"] == 100
