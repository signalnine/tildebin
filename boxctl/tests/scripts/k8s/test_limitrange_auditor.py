"""Tests for limitrange_auditor script."""

import json
import pytest

from boxctl.core.output import Output


class TestLimitrangeAuditor:
    """Tests for limitrange_auditor script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import limitrange_auditor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = limitrange_auditor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_limitranges_returns_issue(self, mock_context, fixtures_dir):
        """Returns 1 when namespaces have no LimitRanges."""
        from scripts.k8s import limitrange_auditor

        namespaces_data = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        limitranges_data = (fixtures_dir / "k8s" / "limitranges_empty.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_data,
                ("kubectl", "get", "limitranges", "-o", "json", "--all-namespaces"): limitranges_data,
            }
        )
        output = Output()

        exit_code = limitrange_auditor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["total_limitranges"] == 0
        # Should report missing limitranges
        missing_issues = [i for i in output.data["issues"] if i.get("type") == "missing_limitrange"]
        assert len(missing_issues) > 0

    def test_valid_limitranges_detected(self, mock_context, fixtures_dir):
        """Detects valid LimitRange configurations."""
        from scripts.k8s import limitrange_auditor

        namespaces_data = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        limitranges_data = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_data,
                ("kubectl", "get", "limitranges", "-o", "json", "--all-namespaces"): limitranges_data,
            }
        )
        output = Output()

        exit_code = limitrange_auditor.run([], output, ctx)

        # Should detect the LimitRanges
        assert output.data["summary"]["total_limitranges"] == 2

    def test_invalid_range_detected(self, mock_context, fixtures_dir):
        """Detects LimitRanges where min > max."""
        from scripts.k8s import limitrange_auditor

        namespaces_data = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        limitranges_data = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_data,
                ("kubectl", "get", "limitranges", "-o", "json", "--all-namespaces"): limitranges_data,
            }
        )
        output = Output()

        exit_code = limitrange_auditor.run([], output, ctx)

        # Should return 1 (issues found)
        assert exit_code == 1
        # Staging has invalid-limits where min > max
        invalid_range_issues = [i for i in output.data["issues"] if i.get("type") == "invalid_range"]
        assert len(invalid_range_issues) > 0

    def test_namespace_filter(self, mock_context, fixtures_dir):
        """--namespace filters to specific namespace."""
        from scripts.k8s import limitrange_auditor

        namespaces_data = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        limitranges_data = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_data,
                ("kubectl", "get", "limitranges", "-o", "json", "-n", "production"): limitranges_data,
            }
        )
        output = Output()

        exit_code = limitrange_auditor.run(["-n", "production"], output, ctx)

        # Should work with namespace filter
        assert exit_code in (0, 1)

    def test_include_system_namespaces(self, mock_context, fixtures_dir):
        """--include-system includes kube-system etc in coverage."""
        from scripts.k8s import limitrange_auditor

        namespaces_data = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        limitranges_data = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_data,
                ("kubectl", "get", "limitranges", "-o", "json", "--all-namespaces"): limitranges_data,
            }
        )
        output = Output()

        exit_code = limitrange_auditor.run(["--include-system"], output, ctx)

        # Coverage should include more namespaces
        assert output.data["coverage"]["total_namespaces"] > 0

    def test_coverage_percent_calculated(self, mock_context, fixtures_dir):
        """Coverage percentage is calculated correctly."""
        from scripts.k8s import limitrange_auditor

        namespaces_data = (fixtures_dir / "k8s" / "namespaces.json").read_text()
        limitranges_data = (fixtures_dir / "k8s" / "limitranges.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "namespaces", "-o", "json"): namespaces_data,
                ("kubectl", "get", "limitranges", "-o", "json", "--all-namespaces"): limitranges_data,
            }
        )
        output = Output()

        exit_code = limitrange_auditor.run([], output, ctx)

        # Coverage percent should be present
        assert "coverage_percent" in output.data["coverage"]
        assert 0 <= output.data["coverage"]["coverage_percent"] <= 100
