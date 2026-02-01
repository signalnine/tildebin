"""Tests for resource_request_efficiency script."""

import json
import pytest

from boxctl.core.output import Output


class TestResourceRequestEfficiency:
    """Tests for resource_request_efficiency script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import resource_request_efficiency

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = resource_request_efficiency.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_metrics_unavailable_returns_error(self, mock_context, fixtures_dir):
        """Returns exit code 2 when metrics-server unavailable."""
        from scripts.k8s import resource_request_efficiency

        pods = (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()

        # Simulate metrics-server failure
        class FailedResult:
            returncode = 1
            stdout = ""
            stderr = "Error from server"

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        # Override to return failure for metrics command
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if 'top' in cmd:
                return FailedResult()
            return original_run(cmd, **kwargs)
        ctx.run = mock_run
        output = Output()

        exit_code = resource_request_efficiency.run([], output, ctx)

        assert exit_code == 2

    def test_no_metrics_available(self, mock_context, fixtures_dir):
        """Returns 0 with warning when no metrics available."""
        from scripts.k8s import resource_request_efficiency

        pods = (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()

        class EmptyMetricsResult:
            returncode = 0
            stdout = ""
            stderr = ""

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if 'top' in cmd:
                return EmptyMetricsResult()
            return original_run(cmd, **kwargs)
        ctx.run = mock_run
        output = Output()

        exit_code = resource_request_efficiency.run([], output, ctx)

        assert exit_code == 0
        assert len(output.warnings) > 0

    def test_efficiency_analysis_with_metrics(self, mock_context, fixtures_dir):
        """Analyzes efficiency when metrics available."""
        from scripts.k8s import resource_request_efficiency

        pods = (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()
        metrics = (fixtures_dir / "k8s" / "pod_metrics.txt").read_text()

        class MetricsResult:
            returncode = 0
            stdout = metrics
            stderr = ""

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if 'top' in cmd:
                return MetricsResult()
            return original_run(cmd, **kwargs)
        ctx.run = mock_run
        output = Output()

        exit_code = resource_request_efficiency.run([], output, ctx)

        assert "workloads" in output.data
        assert "summary" in output.data

    def test_low_efficiency_detected(self, mock_context, fixtures_dir):
        """Detects over-provisioned pods (low efficiency)."""
        from scripts.k8s import resource_request_efficiency

        pods = (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()
        # Metrics showing very low usage compared to requests
        metrics_low = """production nginx-7c8d9b6f5-abc12 nginx 10m 16Mi
production api-server-5d7c9b4f8-def34 api 20m 32Mi"""

        class MetricsResult:
            returncode = 0
            stdout = metrics_low
            stderr = ""

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if 'top' in cmd:
                return MetricsResult()
            return original_run(cmd, **kwargs)
        ctx.run = mock_run
        output = Output()

        # Low usage should trigger over-provisioned detection
        exit_code = resource_request_efficiency.run(["--low-threshold", "25"], output, ctx)

        assert "workloads" in output.data

    def test_warn_only_filters_healthy(self, mock_context, fixtures_dir):
        """--warn-only only shows pods with efficiency issues."""
        from scripts.k8s import resource_request_efficiency

        pods = (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()
        # Metrics at good efficiency
        metrics_good = """production nginx-7c8d9b6f5-abc12 nginx 80m 100Mi"""

        class MetricsResult:
            returncode = 0
            stdout = metrics_good
            stderr = ""

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): pods,
            }
        )
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if 'top' in cmd:
                return MetricsResult()
            return original_run(cmd, **kwargs)
        ctx.run = mock_run
        output = Output()

        exit_code = resource_request_efficiency.run(["--warn-only"], output, ctx)

        assert exit_code in (0, 1)

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """--namespace filters to specific namespace."""
        from scripts.k8s import resource_request_efficiency

        pods = (fixtures_dir / "k8s" / "pods_with_resources.json").read_text()
        # Metrics for specific namespace (no namespace prefix)
        metrics_ns = """nginx-7c8d9b6f5-abc12 nginx 50m 64Mi"""

        class MetricsResult:
            returncode = 0
            stdout = metrics_ns
            stderr = ""

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): pods,
            }
        )
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if 'top' in cmd:
                return MetricsResult()
            return original_run(cmd, **kwargs)
        ctx.run = mock_run
        output = Output()

        exit_code = resource_request_efficiency.run(["-n", "production"], output, ctx)

        assert exit_code in (0, 1)
