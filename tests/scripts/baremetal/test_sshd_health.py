"""Tests for sshd_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def sshd_config_secure(fixtures_dir):
    """Load secure sshd configuration."""
    return (fixtures_dir / "services" / "sshd_config_secure.txt").read_text()


@pytest.fixture
def sshd_config_insecure(fixtures_dir):
    """Load insecure sshd configuration."""
    return (fixtures_dir / "services" / "sshd_config_insecure.txt").read_text()


@pytest.fixture
def who_output_normal(fixtures_dir):
    """Load normal who output."""
    return (fixtures_dir / "services" / "who_output_normal.txt").read_text()


class TestSshdHealth:
    """Tests for sshd_health script."""

    def test_missing_sshd_returns_error(self, mock_context):
        """Returns exit code 2 when sshd not available."""
        from scripts.baremetal import sshd_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = sshd_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("sshd" in e.lower() for e in output.errors)

    def test_sshd_not_running_returns_error(self, mock_context):
        """Returns exit code 2 when sshd is not running."""
        from scripts.baremetal import sshd_health
        import subprocess

        ctx = mock_context(
            tools_available=["sshd", "systemctl", "pgrep"],
            command_outputs={
                ("systemctl", "is-active", "sshd"): "inactive\n",
                ("systemctl", "is-active", "ssh"): "inactive\n",
            },
        )
        # Mock pgrep to return non-zero (no process found)
        original_run = ctx.run
        def mock_run(cmd, **kwargs):
            if cmd == ["pgrep", "-x", "sshd"]:
                return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="")
            return original_run(cmd, **kwargs)
        ctx.run = mock_run
        output = Output()

        exit_code = sshd_health.run([], output, ctx)

        assert exit_code == 2
        assert output.data.get("running") is False

    def test_sshd_healthy_returns_zero(self, mock_context, sshd_config_secure, who_output_normal):
        """Returns 0 when sshd is running with secure config."""
        from scripts.baremetal import sshd_health

        ctx = mock_context(
            tools_available=["sshd", "systemctl", "pgrep", "ss", "who"],
            command_outputs={
                ("systemctl", "is-active", "sshd"): "active\n",
                ("sshd", "-T"): sshd_config_secure,
                ("ss", "-tn", "state", "established", "( dport = :22 or sport = :22 )"): "State Recv-Q\nESTAB 0\nESTAB 0\n",
                ("pgrep", "-c", "sshd"): "3\n",
                ("who",): who_output_normal,
            },
        )
        output = Output()

        exit_code = sshd_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data.get("running") is True

    def test_insecure_config_returns_warning(self, mock_context, sshd_config_insecure, who_output_normal):
        """Returns 1 when sshd has insecure configuration."""
        from scripts.baremetal import sshd_health

        ctx = mock_context(
            tools_available=["sshd", "systemctl", "pgrep", "ss", "who"],
            command_outputs={
                ("systemctl", "is-active", "sshd"): "active\n",
                ("sshd", "-T"): sshd_config_insecure,
                ("ss", "-tn", "state", "established", "( dport = :22 or sport = :22 )"): "State Recv-Q\n",
                ("pgrep", "-c", "sshd"): "1\n",
                ("who",): "",
            },
        )
        output = Output()

        exit_code = sshd_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data.get("running") is True
        issues = output.data.get("issues", [])
        # Check for critical issue (permitemptypasswords)
        assert any(i["severity"] == "critical" for i in issues)

    def test_verbose_output_includes_details(self, mock_context, sshd_config_secure, who_output_normal):
        """--verbose includes additional details."""
        from scripts.baremetal import sshd_health

        ctx = mock_context(
            tools_available=["sshd", "systemctl", "pgrep", "ss", "who"],
            command_outputs={
                ("systemctl", "is-active", "sshd"): "active\n",
                ("sshd", "-T"): sshd_config_secure,
                ("ss", "-tn", "state", "established", "( dport = :22 or sport = :22 )"): "State Recv-Q\n",
                ("pgrep", "-c", "sshd"): "3\n",
                ("who",): who_output_normal,
            },
        )
        output = Output()

        exit_code = sshd_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        # Verbose should include user connections
        assert "by_user" in output.data.get("connections", {})

    def test_warn_only_filters_info_messages(self, mock_context, sshd_config_insecure, who_output_normal):
        """--warn-only filters out info-level messages."""
        from scripts.baremetal import sshd_health

        ctx = mock_context(
            tools_available=["sshd", "systemctl", "pgrep", "ss", "who"],
            command_outputs={
                ("systemctl", "is-active", "sshd"): "active\n",
                ("sshd", "-T"): sshd_config_insecure,
                ("ss", "-tn", "state", "established", "( dport = :22 or sport = :22 )"): "State Recv-Q\n",
                ("pgrep", "-c", "sshd"): "1\n",
                ("who",): "",
            },
        )
        output = Output()

        exit_code = sshd_health.run(["--warn-only"], output, ctx)

        issues = output.data.get("issues", [])
        # No info-level issues should be present
        assert not any(i["severity"] == "info" for i in issues)

    def test_ssh_alternative_service_name(self, mock_context, sshd_config_secure, who_output_normal):
        """Checks 'ssh' service name when 'sshd' fails."""
        from scripts.baremetal import sshd_health

        ctx = mock_context(
            tools_available=["sshd", "systemctl", "pgrep", "ss", "who"],
            command_outputs={
                ("systemctl", "is-active", "sshd"): "inactive\n",
                ("systemctl", "is-active", "ssh"): "active\n",
                ("sshd", "-T"): sshd_config_secure,
                ("ss", "-tn", "state", "established", "( dport = :22 or sport = :22 )"): "State Recv-Q\n",
                ("pgrep", "-c", "sshd"): "1\n",
                ("who",): "",
            },
        )
        output = Output()

        exit_code = sshd_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data.get("running") is True
