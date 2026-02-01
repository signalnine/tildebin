"""Tests for suid_sgid_audit script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def find_suid_clean(fixtures_dir):
    """Load clean SUID find output."""
    return (fixtures_dir / "security" / "find_suid_clean.txt").read_text()


@pytest.fixture
def find_suid_issues(fixtures_dir):
    """Load SUID find output with suspicious files."""
    return (fixtures_dir / "security" / "find_suid_issues.txt").read_text()


class TestSuidSgidAudit:
    """Tests for suid_sgid_audit script."""

    def test_missing_find_returns_error(self, mock_context):
        """Returns exit code 2 when find not available."""
        from scripts.baremetal import suid_sgid_audit

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = suid_sgid_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("find" in e.lower() for e in output.errors)

    def test_no_suid_files_found(self, mock_context):
        """Returns 0 when no SUID/SGID files exist."""
        from scripts.baremetal import suid_sgid_audit

        ctx = mock_context(
            tools_available=["find"],
            command_outputs={
                tuple(['find', '/', '-path', '/proc', '-prune', '-o',
                       '-path', '/sys', '-prune', '-o', '-path', '/run', '-prune', '-o',
                       '-path', '/dev', '-prune', '-o',
                       '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print']): "",
            }
        )
        output = Output()

        exit_code = suid_sgid_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data['total_found'] == 0

    def test_clean_suid_files(self, mock_context, find_suid_clean):
        """Returns 0 when all SUID files are expected."""
        from scripts.baremetal import suid_sgid_audit

        ctx = mock_context(
            tools_available=["find"],
            command_outputs={
                tuple(['find', '/', '-path', '/proc', '-prune', '-o',
                       '-path', '/sys', '-prune', '-o', '-path', '/run', '-prune', '-o',
                       '-path', '/dev', '-prune', '-o',
                       '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print']): find_suid_clean,
            }
        )
        output = Output()

        exit_code = suid_sgid_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data['suspicious_count'] == 0

    def test_suspicious_location_detected(self, mock_context, find_suid_issues):
        """Returns 1 when SUID files in suspicious locations."""
        from scripts.baremetal import suid_sgid_audit

        ctx = mock_context(
            tools_available=["find"],
            command_outputs={
                tuple(['find', '/', '-path', '/proc', '-prune', '-o',
                       '-path', '/sys', '-prune', '-o', '-path', '/run', '-prune', '-o',
                       '-path', '/dev', '-prune', '-o',
                       '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print']): find_suid_issues,
            }
        )
        output = Output()

        exit_code = suid_sgid_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data['suspicious_count'] >= 1
        assert '/tmp/suspicious_binary' in output.data['suspicious_locations']

    def test_home_directory_suspicious(self, mock_context):
        """SUID files in /home are flagged as suspicious."""
        from scripts.baremetal import suid_sgid_audit

        find_output = "/usr/bin/passwd\n/home/user/malware\n"
        ctx = mock_context(
            tools_available=["find"],
            command_outputs={
                tuple(['find', '/', '-path', '/proc', '-prune', '-o',
                       '-path', '/sys', '-prune', '-o', '-path', '/run', '-prune', '-o',
                       '-path', '/dev', '-prune', '-o',
                       '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print']): find_output,
            }
        )
        output = Output()

        exit_code = suid_sgid_audit.run([], output, ctx)

        assert exit_code == 1
        assert '/home/user/malware' in output.data['suspicious_locations']

    def test_custom_path_search(self, mock_context, find_suid_clean):
        """--path flag changes search directory."""
        from scripts.baremetal import suid_sgid_audit

        ctx = mock_context(
            tools_available=["find"],
            command_outputs={
                tuple(['find', '/usr', '-path', '/proc', '-prune', '-o',
                       '-path', '/sys', '-prune', '-o', '-path', '/run', '-prune', '-o',
                       '-path', '/dev', '-prune', '-o',
                       '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print']): find_suid_clean,
            }
        )
        output = Output()

        exit_code = suid_sgid_audit.run(["--path", "/usr"], output, ctx)

        assert exit_code == 0

    def test_no_expected_check(self, mock_context):
        """--no-expected-check skips comparing to known-good list."""
        from scripts.baremetal import suid_sgid_audit

        # Only unexpected binary but no suspicious location
        find_output = "/usr/local/bin/custom_suid\n"
        ctx = mock_context(
            tools_available=["find"],
            command_outputs={
                tuple(['find', '/', '-path', '/proc', '-prune', '-o',
                       '-path', '/sys', '-prune', '-o', '-path', '/run', '-prune', '-o',
                       '-path', '/dev', '-prune', '-o',
                       '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print']): find_output,
            }
        )
        output = Output()

        exit_code = suid_sgid_audit.run(["--no-expected-check"], output, ctx)

        # Should return 0 because no suspicious location
        assert exit_code == 0
        assert output.data['unexpected_count'] == 0
