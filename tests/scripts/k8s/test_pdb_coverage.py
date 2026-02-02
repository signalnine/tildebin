"""Tests for k8s pdb_coverage script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestPdbCoverage:
    """Tests for pdb_coverage."""

    def test_all_covered(self, capsys):
        """Workloads with PDB coverage return exit code 0."""
        from scripts.k8s.pdb_coverage import run

        # Deployment with matching PDB
        deployments = {
            "items": [
                {
                    "metadata": {"name": "nginx", "namespace": "default"},
                    "spec": {
                        "replicas": 3,
                        "selector": {"matchLabels": {"app": "nginx"}}
                    },
                    "status": {"readyReplicas": 3}
                }
            ]
        }

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "nginx-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 2,
                        "selector": {"matchLabels": {"app": "nginx"}}
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "nginx" in captured.out
        assert "OK" in captured.out

    def test_missing_pdb(self, capsys):
        """Workloads without PDB return exit code 1."""
        from scripts.k8s.pdb_coverage import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "api-server", "namespace": "production"},
                    "spec": {
                        "replicas": 3,
                        "selector": {"matchLabels": {"app": "api"}}
                    },
                    "status": {"readyReplicas": 3}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "No PDB coverage" in captured.out or "HIGH" in captured.out

    def test_critical_namespace(self, capsys):
        """Critical namespace without PDB shows CRITICAL severity."""
        from scripts.k8s.pdb_coverage import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "coredns", "namespace": "kube-system"},
                    "spec": {
                        "replicas": 2,
                        "selector": {"matchLabels": {"app": "coredns"}}
                    },
                    "status": {"readyReplicas": 2}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_restrictive_pdb(self, capsys):
        """PDB with maxUnavailable=0 shows WARNING."""
        from scripts.k8s.pdb_coverage import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "database", "namespace": "default"},
                    "spec": {
                        "replicas": 3,
                        "selector": {"matchLabels": {"app": "db"}}
                    },
                    "status": {"readyReplicas": 3}
                }
            ]
        }

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "db-pdb", "namespace": "default"},
                    "spec": {
                        "maxUnavailable": 0,
                        "selector": {"matchLabels": {"app": "db"}}
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "blocks all evictions" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.pdb_coverage import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "web", "namespace": "default"},
                    "spec": {
                        "replicas": 2,
                        "selector": {"matchLabels": {"app": "web"}}
                    },
                    "status": {"readyReplicas": 2}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "workloads" in data
        assert "total_workloads" in data["summary"]
        assert "workloads_without_pdb" in data["summary"]

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters OK workloads."""
        from scripts.k8s.pdb_coverage import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "covered", "namespace": "default"},
                    "spec": {
                        "replicas": 3,
                        "selector": {"matchLabels": {"app": "covered"}}
                    },
                    "status": {"readyReplicas": 3}
                }
            ]
        }

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "covered-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 2,
                        "selector": {"matchLabels": {"app": "covered"}}
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # With warn-only, OK entries should not appear in the output (only header)
        lines = [l for l in captured.out.strip().split("\n") if "covered" in l.lower() and "OK" in l]
        assert len(lines) == 0

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.pdb_coverage import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter uses correct kubectl args."""
        from scripts.k8s.pdb_coverage import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "-n", "production"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "-n", "production"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "-n", "production"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "-n", "production"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        # Verify correct commands were run
        assert ("kubectl", "get", "pdb", "-o", "json", "-n", "production") in [
            tuple(cmd) for cmd in context.commands_run
        ]

    def test_single_replica_low_severity(self, capsys):
        """Single replica workload without PDB shows LOW severity."""
        from scripts.k8s.pdb_coverage import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "singleton", "namespace": "default"},
                    "spec": {
                        "replicas": 1,
                        "selector": {"matchLabels": {"app": "singleton"}}
                    },
                    "status": {"readyReplicas": 1}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        # LOW severity doesn't trigger exit code 1
        assert result == 0
        captured = capsys.readouterr()
        assert "LOW" in captured.out
        assert "Single replica" in captured.out

    def test_summary_set(self):
        """Summary is set correctly."""
        from scripts.k8s.pdb_coverage import run

        deployments = {
            "items": [
                {
                    "metadata": {"name": "app", "namespace": "default"},
                    "spec": {
                        "replicas": 3,
                        "selector": {"matchLabels": {"app": "app"}}
                    },
                    "status": {"readyReplicas": 3}
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps(deployments),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "replicasets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "workloads=" in output.summary
        assert "critical=" in output.summary
        assert "high=" in output.summary
