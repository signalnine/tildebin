"""Tests for authorized_keys_audit script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def auth_keys_healthy(fixtures_dir):
    """Load healthy authorized_keys content."""
    return (fixtures_dir / "security" / "authorized_keys_healthy.txt").read_text()


@pytest.fixture
def auth_keys_issues(fixtures_dir):
    """Load authorized_keys with security issues."""
    return (fixtures_dir / "security" / "authorized_keys_issues.txt").read_text()


@pytest.fixture
def passwd_content():
    """Mock /etc/passwd content."""
    return """root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""


class TestAuthorizedKeysAudit:
    """Tests for authorized_keys_audit script."""

    def test_no_authorized_keys_files(self, mock_context, passwd_content):
        """Returns 0 when no authorized_keys files exist."""
        from scripts.baremetal import authorized_keys_audit

        ctx = mock_context(
            file_contents={
                '/etc/passwd': passwd_content,
            }
        )
        output = Output()

        exit_code = authorized_keys_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data['files_scanned'] == 0
        assert output.data['total_keys'] == 0

    def test_healthy_keys_return_zero(self, mock_context, passwd_content, auth_keys_healthy):
        """Returns 0 when all keys are secure."""
        from scripts.baremetal import authorized_keys_audit

        ctx = mock_context(
            file_contents={
                '/etc/passwd': passwd_content,
                '/home/alice/.ssh/authorized_keys': auth_keys_healthy,
            }
        )
        output = Output()

        exit_code = authorized_keys_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data['total_keys'] == 3
        assert output.data['critical_count'] == 0

    def test_dsa_key_detected_as_weak(self, mock_context, passwd_content):
        """DSA keys are flagged as critical weak algorithm."""
        from scripts.baremetal import authorized_keys_audit

        dsa_key = "ssh-dss AAAAB3NzaC1kc3MAAACBAJ weak-dsa@test\n"
        ctx = mock_context(
            file_contents={
                '/etc/passwd': passwd_content,
                '/home/alice/.ssh/authorized_keys': dsa_key,
            }
        )
        output = Output()

        exit_code = authorized_keys_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data['critical_count'] >= 1
        issues = output.data['files'][0]['issues']
        assert any(i['issue'] == 'weak_algorithm' for i in issues)

    def test_unrestricted_root_key_critical(self, mock_context):
        """Unrestricted root keys are flagged as critical."""
        from scripts.baremetal import authorized_keys_audit

        passwd = "root:x:0:0:root:/root:/bin/bash\n"
        root_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxyz root@admin\n"

        ctx = mock_context(
            file_contents={
                '/etc/passwd': passwd,
                '/root/.ssh/authorized_keys': root_key,
            }
        )
        output = Output()

        exit_code = authorized_keys_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data['critical_count'] >= 1
        issues = output.data['files'][0]['issues']
        assert any(i['issue'] == 'unrestricted_root' for i in issues)

    def test_dangerous_command_flagged(self, mock_context, passwd_content):
        """Keys with dangerous command options are flagged."""
        from scripts.baremetal import authorized_keys_audit

        shell_cmd_key = 'command="/bin/bash" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxyz danger@test\n'
        ctx = mock_context(
            file_contents={
                '/etc/passwd': passwd_content,
                '/home/alice/.ssh/authorized_keys': shell_cmd_key,
            }
        )
        output = Output()

        exit_code = authorized_keys_audit.run([], output, ctx)

        assert exit_code == 1
        issues = output.data['files'][0]['issues']
        assert any(i['issue'] == 'dangerous_command' for i in issues)

    def test_user_filter(self, mock_context, passwd_content, auth_keys_healthy):
        """--user flag filters to specific user."""
        from scripts.baremetal import authorized_keys_audit

        ctx = mock_context(
            file_contents={
                '/etc/passwd': passwd_content,
                '/home/alice/.ssh/authorized_keys': auth_keys_healthy,
                '/home/bob/.ssh/authorized_keys': "ssh-dss AAAAB3NzaC1kc3MAAACBAJ weak@bob\n",
            }
        )
        output = Output()

        # Should only check alice, not find bob's weak key
        exit_code = authorized_keys_audit.run(["--user", "alice"], output, ctx)

        assert exit_code == 0
        assert output.data['critical_count'] == 0

    def test_warn_only_filter(self, mock_context, passwd_content):
        """--warn-only hides info-level issues."""
        from scripts.baremetal import authorized_keys_audit

        # Key without from= generates info-level warning only
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxyz test@host\n"
        ctx = mock_context(
            file_contents={
                '/etc/passwd': passwd_content,
                '/home/alice/.ssh/authorized_keys': key,
            }
        )
        output = Output()

        exit_code = authorized_keys_audit.run(["--warn-only"], output, ctx)

        # Info issues shouldn't cause exit 1
        assert exit_code == 0
