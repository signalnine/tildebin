"""Tests for failed_login_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def auth_log_clean(fixtures_dir):
    """Load clean auth log (no failed logins)."""
    return (fixtures_dir / "security" / "auth_log_clean.txt").read_text()


@pytest.fixture
def auth_log_attacks(fixtures_dir):
    """Load auth log with attack attempts."""
    return (fixtures_dir / "security" / "auth_log_attacks.txt").read_text()


class TestFailedLoginMonitor:
    """Tests for failed_login_monitor script."""

    def test_no_log_file_returns_error(self, mock_context):
        """Returns exit code 2 when no auth log found."""
        from scripts.baremetal import failed_login_monitor

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = failed_login_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_clean_log_returns_zero(self, mock_context, auth_log_clean):
        """Returns 0 when no failed logins in log."""
        from scripts.baremetal import failed_login_monitor

        ctx = mock_context(
            file_contents={
                '/var/log/auth.log': auth_log_clean,
            }
        )
        output = Output()

        exit_code = failed_login_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data['total_attempts'] == 0

    def test_attacks_detected(self, mock_context, auth_log_attacks):
        """Detects failed login attempts from attackers."""
        from scripts.baremetal import failed_login_monitor

        ctx = mock_context(
            file_contents={
                '/var/log/auth.log': auth_log_attacks,
            }
        )
        output = Output()

        # Use --all to ignore time filtering (fixture dates are in the past)
        exit_code = failed_login_monitor.run(["--threshold", "5", "--all"], output, ctx)

        assert exit_code == 1
        assert output.data['total_attempts'] > 0
        assert output.data['ips_exceeding_threshold'] >= 1
        assert '192.168.1.100' in output.data['brute_force_alerts']

    def test_threshold_filtering(self, mock_context, auth_log_attacks):
        """Higher threshold means fewer alerts."""
        from scripts.baremetal import failed_login_monitor

        ctx = mock_context(
            file_contents={
                '/var/log/auth.log': auth_log_attacks,
            }
        )
        output = Output()

        # With high threshold, no alerts (use --all to parse all entries)
        exit_code = failed_login_monitor.run(["--threshold", "100", "--all"], output, ctx)

        assert exit_code == 0
        assert output.data['ips_exceeding_threshold'] == 0

    def test_custom_log_file(self, mock_context, auth_log_attacks):
        """--log-file uses specified path."""
        from scripts.baremetal import failed_login_monitor

        ctx = mock_context(
            file_contents={
                '/var/log/secure': auth_log_attacks,
            }
        )
        output = Output()

        exit_code = failed_login_monitor.run(
            ["--log-file", "/var/log/secure", "--threshold", "5", "--all"],
            output, ctx
        )

        assert exit_code == 1

    def test_invalid_hours_returns_error(self, mock_context, auth_log_clean):
        """Returns error for invalid hours parameter."""
        from scripts.baremetal import failed_login_monitor

        ctx = mock_context(
            file_contents={
                '/var/log/auth.log': auth_log_clean,
            }
        )
        output = Output()

        exit_code = failed_login_monitor.run(["--hours", "0"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_threshold_returns_error(self, mock_context, auth_log_clean):
        """Returns error for invalid threshold parameter."""
        from scripts.baremetal import failed_login_monitor

        ctx = mock_context(
            file_contents={
                '/var/log/auth.log': auth_log_clean,
            }
        )
        output = Output()

        exit_code = failed_login_monitor.run(["--threshold", "-1"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
