"""Tests for k8s annotation_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestAnnotationAudit:
    """Tests for annotation_audit."""

    def test_all_compliant(self, capsys):
        """All pods with required annotations return exit code 0."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "team-platform"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "compliant" in captured.out.lower() or "OK" in captured.out

    def test_missing_annotation(self, capsys):
        """Pods missing required annotations return exit code 1."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {}
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Missing" in captured.out or "non-compliant" in captured.out.lower()

    def test_invalid_annotation_value(self, capsys):
        """Annotations with invalid values return exit code 1."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "invalid-format"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        # Require owner to match team-* pattern
        result = run(["--required", "app.kubernetes.io/owner=team-.*"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid" in captured.out

    def test_valid_annotation_pattern(self, capsys):
        """Annotations matching pattern return exit code 0."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "team-platform"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner=team-.*"], output, context)

        assert result == 0

    def test_forbidden_annotation(self, capsys):
        """Pods with forbidden annotations return exit code 1."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "team-platform",
                            "deprecated.example.com/old-config": "true"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run([
            "--required", "app.kubernetes.io/owner",
            "--forbidden", "deprecated.example.com/old-config"
        ], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Forbidden" in captured.out

    def test_skip_system_namespaces(self, capsys):
        """System namespaces are skipped by default."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "coredns",
                        "namespace": "kube-system",
                        "annotations": {}
                    }
                },
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "team-platform"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner"], output, context)

        # kube-system pod should be skipped, only production pod counts
        assert result == 0

    def test_include_system_namespaces(self, capsys):
        """System namespaces are included with flag."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "coredns",
                        "namespace": "kube-system",
                        "annotations": {}
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner", "--include-system"], output, context)

        # kube-system pod should now be checked and fail
        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "team-platform"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_pods" in data
        assert "compliant_pods" in data
        assert "non_compliant_pods" in data
        assert "annotation_stats" in data
        assert "issues" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {}
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner", "--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Namespace" in captured.out
        assert "Pod" in captured.out

    def test_no_required_annotation_error(self, capsys):
        """Missing --required flag returns exit code 2."""
        from scripts.k8s.annotation_audit import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.annotation_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner"], output, context)

        assert result == 2

    def test_multiple_required_annotations(self, capsys):
        """Multiple required annotations work correctly."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "team-platform",
                            "prometheus.io/scrape": "true"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        result = run(["--required", "app.kubernetes.io/owner,prometheus.io/scrape"], output, context)

        assert result == 0

    def test_summary_set(self):
        """Summary is set correctly."""
        from scripts.k8s.annotation_audit import run

        pods = {
            "items": [
                {
                    "metadata": {
                        "name": "web-pod",
                        "namespace": "production",
                        "annotations": {
                            "app.kubernetes.io/owner": "team-platform"
                        }
                    }
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(pods),
            },
        )
        output = Output()

        run(["--required", "app.kubernetes.io/owner"], output, context)

        assert "total=" in output.summary
        assert "compliant=" in output.summary
        assert "non_compliant=" in output.summary
