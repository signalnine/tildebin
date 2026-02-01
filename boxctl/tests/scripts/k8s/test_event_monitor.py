"""Tests for k8s event_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def events_normal(fixtures_dir):
    """Load normal events fixture."""
    return (fixtures_dir / "k8s" / "events_normal.json").read_text()


@pytest.fixture
def events_warnings(fixtures_dir):
    """Load events with warnings fixture."""
    return (fixtures_dir / "k8s" / "events_warnings.json").read_text()


@pytest.fixture
def events_errors(fixtures_dir):
    """Load events with errors fixture."""
    return (fixtures_dir / "k8s" / "events_errors.json").read_text()


@pytest.fixture
def events_empty(fixtures_dir):
    """Load empty events fixture."""
    return (fixtures_dir / "k8s" / "events_empty.json").read_text()


@pytest.fixture
def events_namespace_production(fixtures_dir):
    """Load production namespace events fixture."""
    return (fixtures_dir / "k8s" / "events_namespace_production.json").read_text()


class TestEventMonitor:
    """Tests for event_monitor script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import event_monitor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = event_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_events_returns_healthy(self, mock_context, events_empty):
        """Returns 0 when no events found."""
        from scripts.k8s import event_monitor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): events_empty,
            }
        )
        output = Output()

        exit_code = event_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["error_count"] == 0
        assert output.data["summary"]["warning_count"] == 0

    def test_normal_events_returns_healthy(self, mock_context, events_normal):
        """Returns 0 when only normal events present."""
        from scripts.k8s import event_monitor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): events_normal,
            }
        )
        output = Output()

        exit_code = event_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["error_count"] == 0
        assert output.data["summary"]["warning_count"] == 0

    def test_warning_events_returns_issues(self, mock_context, events_warnings):
        """Returns 1 when warning events detected."""
        from scripts.k8s import event_monitor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): events_warnings,
            }
        )
        output = Output()

        exit_code = event_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["warning_count"] == 3
        assert len(output.data["warnings"]) == 3

    def test_error_events_returns_issues(self, mock_context, events_errors):
        """Returns 1 when error events detected."""
        from scripts.k8s import event_monitor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): events_errors,
            }
        )
        output = Output()

        exit_code = event_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["warning_count"] == 4

    def test_namespace_filter(self, mock_context, events_namespace_production):
        """Filters events by namespace."""
        from scripts.k8s import event_monitor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "events", "-o", "json", "-n", "production"): events_namespace_production,
            }
        )
        output = Output()

        exit_code = event_monitor.run(["-n", "production"], output, ctx)

        assert exit_code == 1
        # All events should be from production namespace
        for warning in output.data.get("warnings", []):
            assert warning["namespace"] == "production"

    def test_warn_only_mode(self, mock_context, events_warnings):
        """--warn-only filters to show only warnings."""
        from scripts.k8s import event_monitor

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "events", "-o", "json", "--all-namespaces"): events_warnings,
            }
        )
        output = Output()

        exit_code = event_monitor.run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # Only warnings should be in output data
        assert "warnings" in output.data
        assert output.data["summary"]["warning_count"] > 0
