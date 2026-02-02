"""Tests for k8s pdb_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestPdbHealth:
    """Tests for pdb_health."""

    def test_healthy_pdbs(self, capsys):
        """Healthy PDBs return exit code 0."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "nginx-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 1,
                        "selector": {"matchLabels": {"app": "nginx"}}
                    },
                    "status": {
                        "currentHealthy": 3,
                        "desiredHealthy": 1,
                        "disruptionsAllowed": 2,
                        "expectedPods": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out.lower()

    def test_blocking_pdb(self, capsys):
        """PDB blocking disruptions returns exit code 1."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "strict-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 3,
                        "selector": {"matchLabels": {"app": "strict"}}
                    },
                    "status": {
                        "currentHealthy": 3,
                        "desiredHealthy": 3,
                        "disruptionsAllowed": 0,
                        "expectedPods": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out or "block" in captured.out.lower()

    def test_no_matching_pods(self, capsys):
        """PDB with no matching pods shows warning."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "orphan-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 1,
                        "selector": {"matchLabels": {"app": "nonexistent"}}
                    },
                    "status": {
                        "currentHealthy": 0,
                        "desiredHealthy": 0,
                        "disruptionsAllowed": 0,
                        "expectedPods": 0
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "No pods match" in captured.out

    def test_unhealthy_pods(self, capsys):
        """PDB with unhealthy pods shows warning."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "partial-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 2,
                        "selector": {"matchLabels": {"app": "partial"}}
                    },
                    "status": {
                        "currentHealthy": 2,
                        "desiredHealthy": 2,
                        "disruptionsAllowed": 0,
                        "expectedPods": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "unhealthy" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "test-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 1,
                        "selector": {"matchLabels": {"app": "test"}}
                    },
                    "status": {
                        "currentHealthy": 2,
                        "desiredHealthy": 1,
                        "disruptionsAllowed": 1,
                        "expectedPods": 2
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "pdbs" in data
        assert "summary" in data
        assert "total_pdbs" in data["summary"]
        assert "critical_issues" in data["summary"]
        assert "blocking_maintenance" in data["summary"]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "test-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 1,
                        "selector": {"matchLabels": {"app": "test"}}
                    },
                    "status": {
                        "currentHealthy": 2,
                        "desiredHealthy": 1,
                        "disruptionsAllowed": 1,
                        "expectedPods": 2
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out
        assert "NAME" in captured.out
        assert "HEALTHY" in captured.out
        assert "STATUS" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy PDBs."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "healthy-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 1,
                        "selector": {"matchLabels": {"app": "healthy"}}
                    },
                    "status": {
                        "currentHealthy": 3,
                        "desiredHealthy": 1,
                        "disruptionsAllowed": 2,
                        "expectedPods": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No PDB issues detected" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.pdb_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_no_pdbs(self, capsys):
        """No PDBs returns exit code 0."""
        from scripts.k8s.pdb_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No PodDisruptionBudgets found" in captured.out

    def test_misconfigured_min_available(self, capsys):
        """minAvailable > expectedPods shows critical."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "bad-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 5,
                        "selector": {"matchLabels": {"app": "bad"}}
                    },
                    "status": {
                        "currentHealthy": 3,
                        "desiredHealthy": 5,
                        "disruptionsAllowed": 0,
                        "expectedPods": 3
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "minAvailable" in captured.out

    def test_summary_set(self):
        """Summary is set correctly."""
        from scripts.k8s.pdb_health import run

        pdbs = {
            "items": [
                {
                    "metadata": {"name": "test-pdb", "namespace": "default"},
                    "spec": {
                        "minAvailable": 1,
                        "selector": {"matchLabels": {"app": "test"}}
                    },
                    "status": {
                        "currentHealthy": 2,
                        "desiredHealthy": 1,
                        "disruptionsAllowed": 1,
                        "expectedPods": 2
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pdb", "-o", "json", "--all-namespaces"): json.dumps(pdbs),
                ("kubectl", "get", "deployments", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
                ("kubectl", "get", "statefulsets", "-o", "json", "--all-namespaces"): json.dumps({"items": []}),
            },
        )
        output = Output()

        run([], output, context)

        assert "pdbs=" in output.summary
        assert "critical=" in output.summary
        assert "blocking=" in output.summary
