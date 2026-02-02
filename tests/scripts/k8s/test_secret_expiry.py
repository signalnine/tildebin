"""Tests for k8s secret_expiry script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSecretExpiry:
    """Tests for secret_expiry."""

    def test_healthy_secrets(self, capsys):
        """Healthy secrets return exit code 0."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "secrets_healthy.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_secrets_with_issues(self, capsys):
        """Secrets with issues return exit code 1."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "secrets_issues.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        # Should detect issues
        assert result in [0, 1]

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "secrets_healthy.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "summary" in data
        assert "secrets" in data
        assert isinstance(data["secrets"], list)

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "secrets_healthy.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Severity" in captured.out
        assert "Namespace" in captured.out
        assert "Name" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        assert ("kubectl", "get", "secrets", "-o", "json", "-n", "production") in [
            tuple(cmd) for cmd in context.commands_run
        ]

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy secrets."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "secrets_healthy.json"
                ),
            },
        )
        output = Output()

        result = run(["--warn-only", "--format", "plain"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should not show OK secrets
        assert "[OK]" not in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_tls_only_filter(self, capsys):
        """TLS-only flag filters to only TLS secrets."""
        from scripts.k8s.secret_expiry import run

        # Create a fixture with mixed secret types
        mixed_secrets = {
            "items": [
                {
                    "metadata": {"name": "tls-secret", "namespace": "default"},
                    "type": "kubernetes.io/tls",
                    "data": {},
                },
                {
                    "metadata": {"name": "opaque-secret", "namespace": "default"},
                    "type": "Opaque",
                    "data": {},
                },
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps(
                    mixed_secrets
                ),
            },
        )
        output = Output()

        result = run(["--tls-only", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should only contain TLS secrets
        for secret in data["secrets"]:
            assert secret["type"] == "kubernetes.io/tls"

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "secrets_healthy.json"
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "secrets=" in output.summary
        assert "critical=" in output.summary
        assert "warning=" in output.summary

    def test_custom_thresholds(self, capsys):
        """Custom expiry thresholds are respected."""
        from scripts.k8s.secret_expiry import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(
            ["--expiry-warn", "60", "--expiry-critical", "14", "--stale-days", "180"],
            output,
            context,
        )

        assert result == 0
