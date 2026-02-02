"""Tests for k8s version_skew script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestVersionSkew:
    """Tests for version_skew."""

    def test_compliant_cluster(self, capsys):
        """Compliant cluster returns exit code 0."""
        from scripts.k8s.version_skew import run

        version_data = {
            "serverVersion": {
                "major": "1",
                "minor": "28",
                "gitVersion": "v1.28.0",
            }
        }

        nodes_data = {
            "items": [
                {
                    "metadata": {"name": "node-1"},
                    "status": {
                        "nodeInfo": {"kubeletVersion": "v1.28.0"},
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                },
                {
                    "metadata": {"name": "node-2"},
                    "status": {
                        "nodeInfo": {"kubeletVersion": "v1.27.0"},
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                },
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(version_data),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes_data),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "tier=control-plane", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_version_skew_violation(self, capsys):
        """Version skew violation returns exit code 1."""
        from scripts.k8s.version_skew import run

        version_data = {
            "serverVersion": {
                "major": "1",
                "minor": "28",
                "gitVersion": "v1.28.0",
            }
        }

        nodes_data = {
            "items": [
                {
                    "metadata": {"name": "old-node"},
                    "status": {
                        "nodeInfo": {"kubeletVersion": "v1.24.0"},
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                },
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(version_data),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes_data),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "tier=control-plane", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "old-node" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.version_skew import run

        version_data = {
            "serverVersion": {
                "major": "1",
                "minor": "28",
                "gitVersion": "v1.28.0",
            }
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(version_data),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "tier=control-plane", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "api_server_version" in data
        assert "nodes" in data
        assert "issues" in data
        assert "compliant" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.version_skew import run

        version_data = {
            "serverVersion": {
                "major": "1",
                "minor": "28",
                "gitVersion": "v1.28.0",
            }
        }

        nodes_data = {
            "items": [
                {
                    "metadata": {"name": "node-1"},
                    "status": {
                        "nodeInfo": {"kubeletVersion": "v1.28.0"},
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                },
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(version_data),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes_data),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "tier=control-plane", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Node" in captured.out
        assert "Kubelet Version" in captured.out
        assert "Skew" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.version_skew import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.version_skew import run

        version_data = {
            "serverVersion": {
                "major": "1",
                "minor": "28",
                "gitVersion": "v1.28.0",
            }
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(version_data),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps({"items": []}),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "tier=control-plane", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "nodes=" in output.summary
        assert "issues=" in output.summary

    def test_kubelet_ahead_of_api_server(self, capsys):
        """Kubelet ahead of API server is flagged as warning."""
        from scripts.k8s.version_skew import run

        version_data = {
            "serverVersion": {
                "major": "1",
                "minor": "27",
                "gitVersion": "v1.27.0",
            }
        }

        nodes_data = {
            "items": [
                {
                    "metadata": {"name": "new-node"},
                    "status": {
                        "nodeInfo": {"kubeletVersion": "v1.28.0"},
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                },
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "version", "-o", "json"): json.dumps(version_data),
                ("kubectl", "get", "nodes", "-o", "json"): json.dumps(nodes_data),
                ("kubectl", "get", "pods", "-n", "kube-system", "-l", "tier=control-plane", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "ahead" in captured.out.lower()
