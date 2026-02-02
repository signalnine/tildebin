"""Tests for k8s helm_releases script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


def make_helm_release(
    name: str,
    namespace: str = "default",
    status: str = "deployed",
    chart: str = "my-chart-1.0.0",
    app_version: str = "1.0.0",
    revision: int = 1,
    updated: str = "2024-01-15T10:30:00.123456789Z",
) -> dict:
    """Create a Helm release for testing."""
    return {
        "name": name,
        "namespace": namespace,
        "status": status,
        "chart": chart,
        "app_version": app_version,
        "revision": revision,
        "updated": updated,
    }


class TestHelmReleases:
    """Tests for helm_releases."""

    def test_healthy_releases(self, capsys):
        """Healthy releases return exit code 0."""
        from scripts.k8s.helm_releases import run

        releases = [
            make_helm_release("release-1"),
            make_helm_release("release-2", namespace="production"),
        ]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        assert "release-1" in captured.out
        assert "release-2" in captured.out

    def test_failed_release(self, capsys):
        """Failed release returns exit code 1."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1", status="failed")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[!!]" in captured.out
        assert "failed" in captured.out

    def test_pending_install_release(self, capsys):
        """Pending-install release is flagged."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1", status="pending-install")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "pending-install" in captured.out
        assert "operation in progress" in captured.out

    def test_superseded_release(self, capsys):
        """Superseded release is flagged as failed."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1", status="superseded")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "superseded" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "release-1"
        assert "healthy" in data[0]
        assert "status" in data[0]
        assert "chart" in data[0]

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "STATUS" in captured.out
        assert "NAMESPACE" in captured.out
        assert "NAME" in captured.out
        assert "CHART" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter works correctly."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1", namespace="production")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "-n", "production"): json.dumps(releases),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "production/release-1" in captured.out

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy releases."""
        from scripts.k8s.helm_releases import run

        releases = [
            make_helm_release("healthy-release", status="deployed"),
            make_helm_release("failed-release", status="failed"),
        ]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "failed-release" in captured.out

    def test_no_releases(self, capsys):
        """No releases returns exit code 0 with message."""
        from scripts.k8s.helm_releases import run

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps([]),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No Helm releases found" in captured.out

    def test_empty_output(self, capsys):
        """Empty helm output is handled."""
        from scripts.k8s.helm_releases import run

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): "",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No Helm releases found" in captured.out

    def test_helm_not_found(self, capsys):
        """Missing helm returns exit code 2."""
        from scripts.k8s.helm_releases import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_age_calculation(self, capsys):
        """Age is calculated and displayed."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "Age:" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.helm_releases import run

        releases = [make_helm_release("release-1")]

        context = MockContext(
            tools_available=["helm"],
            command_outputs={
                ("helm", "list", "-o", "json", "--all-namespaces"): json.dumps(releases),
            },
        )
        output = Output()

        run([], output, context)

        assert "releases=" in output.summary
        assert "healthy=" in output.summary
