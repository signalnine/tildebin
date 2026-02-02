"""Tests for mount_security_audit script."""

import pytest

from boxctl.core.output import Output


@pytest.fixture
def mounts_secure():
    """Secure mount configuration."""
    return """/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /boot ext4 rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /var/tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda3 /home ext4 rw,nosuid,nodev,relatime 0 0
/dev/sda4 /var ext4 rw,nosuid,nodev,relatime 0 0
/dev/sda5 /var/log ext4 rw,nosuid,nodev,noexec,relatime 0 0
"""


@pytest.fixture
def mounts_insecure():
    """Insecure mount configuration."""
    return """/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /boot ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,relatime 0 0
tmpfs /var/tmp tmpfs rw,relatime 0 0
tmpfs /dev/shm tmpfs rw,relatime 0 0
/dev/sda3 /home ext4 rw,relatime 0 0
"""


@pytest.fixture
def mounts_partial():
    """Partially secure mount configuration."""
    return """/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,noexec,nosuid,relatime 0 0
tmpfs /dev/shm tmpfs rw,noexec,relatime 0 0
/dev/sda3 /home ext4 rw,nosuid,relatime 0 0
"""


class TestMountSecurityAudit:
    """Tests for mount_security_audit script."""

    def test_missing_proc_mounts_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/mounts not available."""
        from scripts.baremetal import mount_security_audit

        ctx = mock_context(
            tools_available=[],
            file_contents={}
        )
        output = Output()

        exit_code = mount_security_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_secure_mounts_returns_compliant(self, mock_context, mounts_secure):
        """Returns 0 when all mounts are secure."""
        from scripts.baremetal import mount_security_audit

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts_secure,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['non_compliant'] == 0

    def test_insecure_mounts_returns_non_compliant(self, mock_context, mounts_insecure):
        """Returns 1 when mounts are insecure."""
        from scripts.baremetal import mount_security_audit

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts_insecure,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['non_compliant'] > 0

    def test_tmp_requires_noexec_nosuid_nodev(self, mock_context):
        """Verifies /tmp requires noexec, nosuid, nodev."""
        from scripts.baremetal import mount_security_audit

        # /tmp without required options
        mounts = """/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,relatime 0 0
"""
        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run([], output, ctx)

        assert exit_code == 1
        # Find /tmp in non_compliant
        tmp_finding = next(
            (f for f in output.data['non_compliant'] if f['mountpoint'] == '/tmp'),
            None
        )
        assert tmp_finding is not None
        assert 'noexec' in tmp_finding['missing_required']
        assert 'nosuid' in tmp_finding['missing_required']
        assert 'nodev' in tmp_finding['missing_required']

    def test_home_requires_nosuid_nodev(self, mock_context):
        """Verifies /home requires nosuid, nodev."""
        from scripts.baremetal import mount_security_audit

        mounts = """/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
"""
        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run([], output, ctx)

        assert exit_code == 1
        home_finding = next(
            (f for f in output.data['non_compliant'] if f['mountpoint'] == '/home'),
            None
        )
        assert home_finding is not None
        assert 'nosuid' in home_finding['missing_required']
        assert 'nodev' in home_finding['missing_required']

    def test_strict_mode_checks_additional_mounts(self, mock_context):
        """--strict mode checks /opt, /usr, /srv."""
        from scripts.baremetal import mount_security_audit

        mounts = """/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /opt ext4 rw,relatime 0 0
/dev/sda3 /srv ext4 rw,relatime 0 0
"""
        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts,
            }
        )

        # Without strict mode - /opt and /srv not checked
        output = Output()
        exit_code = mount_security_audit.run([], output, ctx)
        non_strict_count = output.data['summary']['total_checked']

        # With strict mode
        output = Output()
        exit_code = mount_security_audit.run(['--strict'], output, ctx)
        strict_count = output.data['summary']['total_checked']

        assert strict_count > non_strict_count

    def test_removable_media_checked(self, mock_context):
        """Removable media mounts are checked for security options."""
        from scripts.baremetal import mount_security_audit

        mounts = """/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /media/usb ext4 rw,relatime 0 0
/dev/sdc1 /mnt/external ext4 rw,relatime 0 0
"""
        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run([], output, ctx)

        assert exit_code == 1
        # Check that removable media findings exist
        removable_findings = [
            f for f in output.data['non_compliant']
            if '/media/' in f['mountpoint'] or '/mnt/' in f['mountpoint']
        ]
        assert len(removable_findings) == 2

    def test_no_removable_flag_skips_removable(self, mock_context):
        """--no-removable skips removable media checks."""
        from scripts.baremetal import mount_security_audit

        mounts = """/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /media/usb ext4 rw,relatime 0 0
"""
        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts,
            }
        )

        # With removable check
        output = Output()
        exit_code = mount_security_audit.run([], output, ctx)
        with_removable = output.data['summary']['total_checked']

        # Without removable check
        output = Output()
        exit_code = mount_security_audit.run(['--no-removable'], output, ctx)
        without_removable = output.data['summary']['total_checked']

        assert with_removable > without_removable

    def test_show_fixes_includes_remediation(self, mock_context, mounts_insecure):
        """--show-fixes includes remediation commands."""
        from scripts.baremetal import mount_security_audit

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts_insecure,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run(['--show-fixes'], output, ctx)

        assert exit_code == 1
        assert 'remediation' in output.data
        assert len(output.data['remediation']) > 0
        # Check that commands contain mount -o remount
        assert any('mount -o remount' in fix['command'] for fix in output.data['remediation'])

    def test_verbose_shows_cis_references(self, mock_context, mounts_insecure):
        """--verbose shows CIS benchmark references."""
        from scripts.baremetal import mount_security_audit

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts_insecure,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run(['--verbose'], output, ctx)

        assert exit_code == 1
        assert 'all_findings' in output.data
        # Check CIS references are present
        tmp_finding = next(
            (f for f in output.data['all_findings'] if f['mountpoint'] == '/tmp'),
            None
        )
        if tmp_finding:
            assert 'cis_ref' in tmp_finding

    def test_compliance_percentage_calculation(self, mock_context, mounts_partial):
        """Compliance percentage is correctly calculated."""
        from scripts.baremetal import mount_security_audit

        ctx = mock_context(
            tools_available=[],
            file_contents={
                '/proc/mounts': mounts_partial,
            }
        )
        output = Output()

        exit_code = mount_security_audit.run([], output, ctx)

        summary = output.data['summary']
        if summary['total_checked'] > 0:
            expected_pct = round(summary['compliant'] / summary['total_checked'] * 100, 1)
            assert summary['compliance_percentage'] == expected_pct
