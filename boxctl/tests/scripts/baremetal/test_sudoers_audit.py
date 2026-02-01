"""Tests for sudoers_audit script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def sudoers_healthy(fixtures_dir):
    """Load healthy sudoers content."""
    return (fixtures_dir / "security" / "sudoers_healthy.txt").read_text()


@pytest.fixture
def sudoers_issues(fixtures_dir):
    """Load sudoers with security issues."""
    return (fixtures_dir / "security" / "sudoers_issues.txt").read_text()


class TestSudoersAudit:
    """Tests for sudoers_audit script."""

    def test_missing_sudoers_returns_error(self, mock_context):
        """Returns exit code 2 when sudoers file not found."""
        from scripts.baremetal import sudoers_audit

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = sudoers_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_sudoers_returns_zero(self, mock_context, sudoers_healthy):
        """Returns 0 when sudoers has good security settings."""
        from scripts.baremetal import sudoers_audit

        ctx = mock_context(
            file_contents={
                '/etc/sudoers': sudoers_healthy,
            }
        )
        output = Output()

        exit_code = sudoers_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data['critical_count'] == 0
        assert output.data['warning_count'] == 0

    def test_nopasswd_all_critical(self, mock_context):
        """NOPASSWD with ALL is flagged as critical."""
        from scripts.baremetal import sudoers_audit

        sudoers = """Defaults env_reset
Defaults secure_path="/usr/bin:/bin"
deploy  ALL=(ALL) NOPASSWD: ALL
"""
        ctx = mock_context(
            file_contents={
                '/etc/sudoers': sudoers,
            }
        )
        output = Output()

        exit_code = sudoers_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data['critical_count'] >= 1
        assert any(i['type'] == 'nopasswd' and i['severity'] == 'critical'
                   for i in output.data['issues'])

    def test_nopasswd_specific_warning(self, mock_context):
        """NOPASSWD for specific commands is a warning."""
        from scripts.baremetal import sudoers_audit

        sudoers = """Defaults env_reset
Defaults secure_path="/usr/bin:/bin"
backup  ALL=(root) NOPASSWD: /usr/bin/rsync
"""
        ctx = mock_context(
            file_contents={
                '/etc/sudoers': sudoers,
            }
        )
        output = Output()

        exit_code = sudoers_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data['warning_count'] >= 1
        assert any(i['type'] == 'nopasswd' and i['severity'] == 'warning'
                   for i in output.data['issues'])

    def test_missing_env_reset_warning(self, mock_context):
        """Missing env_reset default is flagged."""
        from scripts.baremetal import sudoers_audit

        sudoers = """# No Defaults env_reset
Defaults secure_path="/usr/bin:/bin"
root ALL=(ALL) ALL
"""
        ctx = mock_context(
            file_contents={
                '/etc/sudoers': sudoers,
            }
        )
        output = Output()

        exit_code = sudoers_audit.run([], output, ctx)

        assert exit_code == 1
        assert any(i['type'] == 'missing_default' for i in output.data['issues'])

    def test_negative_timeout_warning(self, mock_context):
        """Negative timestamp_timeout is flagged."""
        from scripts.baremetal import sudoers_audit

        sudoers = """Defaults env_reset
Defaults secure_path="/usr/bin:/bin"
Defaults timestamp_timeout=-1
root ALL=(ALL) ALL
"""
        ctx = mock_context(
            file_contents={
                '/etc/sudoers': sudoers,
            }
        )
        output = Output()

        exit_code = sudoers_audit.run([], output, ctx)

        assert exit_code == 1
        assert any(i['type'] == 'timestamp_timeout' for i in output.data['issues'])

    def test_warn_only_filters_info(self, mock_context):
        """--warn-only hides info-level issues."""
        from scripts.baremetal import sudoers_audit

        # SETENV is info-level only
        sudoers = """Defaults env_reset
Defaults secure_path="/usr/bin:/bin"
developer ALL=(ALL) SETENV: /usr/bin/make
"""
        ctx = mock_context(
            file_contents={
                '/etc/sudoers': sudoers,
            }
        )
        output = Output()

        exit_code = sudoers_audit.run(["--warn-only"], output, ctx)

        # SETENV alone is info-level, so no warnings/critical
        assert exit_code == 0
        # With warn-only, info issues should be filtered from output
        assert all(i['severity'] != 'info' for i in output.data['issues'])
