"""Tests for secret_audit script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


class TestSecretAudit:
    """Tests for secret_audit script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import secret_audit

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = secret_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_healthy_secrets_no_issues(self, mock_context, fixtures_dir):
        """Returns 0 when secrets are healthy."""
        from scripts.k8s import secret_audit

        secrets = (fixtures_dir / "k8s" / "secrets_healthy.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): secrets,
            }
        )
        output = Output()

        exit_code = secret_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["critical"] == 0
        assert output.data["summary"]["warning"] == 0

    def test_detects_stale_secrets(self, mock_context, fixtures_dir):
        """Detects secrets older than stale threshold."""
        from scripts.k8s import secret_audit

        secrets = (fixtures_dir / "k8s" / "secrets_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): secrets,
            }
        )
        output = Output()

        # Use a low stale threshold to trigger detection
        exit_code = secret_audit.run(["--stale-days", "30"], output, ctx)

        assert exit_code == 1
        # Find the stale secret
        stale_secrets = [
            s for s in output.data["secrets"]
            if any("stale" in issue.lower() or "days old" in issue.lower() for issue in s.get("issues", []))
        ]
        assert len(stale_secrets) > 0

    def test_detects_missing_tls_cert(self, mock_context, fixtures_dir):
        """Detects TLS secrets missing tls.crt."""
        from scripts.k8s import secret_audit

        secrets = (fixtures_dir / "k8s" / "secrets_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): secrets,
            }
        )
        output = Output()

        exit_code = secret_audit.run([], output, ctx)

        # Find the broken-tls secret
        broken_tls = next(
            (s for s in output.data["secrets"] if s["name"] == "broken-tls"),
            None
        )
        assert broken_tls is not None
        assert broken_tls["has_issue"] is True
        assert any("tls.crt" in issue for issue in broken_tls["issues"])

    def test_skips_service_account_tokens(self, mock_context, fixtures_dir):
        """Skips service account tokens by default."""
        from scripts.k8s import secret_audit

        secrets = (fixtures_dir / "k8s" / "secrets_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): secrets,
            }
        )
        output = Output()

        exit_code = secret_audit.run([], output, ctx)

        # Service account token should not be in output
        sa_token = next(
            (s for s in output.data["secrets"] if s["name"] == "sa-token"),
            None
        )
        assert sa_token is None

    def test_verbose_includes_sa_tokens(self, mock_context, fixtures_dir):
        """--verbose includes service account tokens."""
        from scripts.k8s import secret_audit

        secrets = (fixtures_dir / "k8s" / "secrets_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): secrets,
            }
        )
        output = Output()

        exit_code = secret_audit.run(["--verbose"], output, ctx)

        # Service account token should be in output
        sa_token = next(
            (s for s in output.data["secrets"] if s["name"] == "sa-token"),
            None
        )
        assert sa_token is not None
        assert sa_token.get("skipped") is True

    def test_tls_only_filters_non_tls(self, mock_context, fixtures_dir):
        """--tls-only only checks TLS secrets."""
        from scripts.k8s import secret_audit

        secrets = (fixtures_dir / "k8s" / "secrets_issues.json").read_text()

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "secrets", "-o", "json", "--all-namespaces"): secrets,
            }
        )
        output = Output()

        exit_code = secret_audit.run(["--tls-only"], output, ctx)

        # Only TLS secrets should be in output
        for secret in output.data["secrets"]:
            assert secret["type"] == "kubernetes.io/tls"
