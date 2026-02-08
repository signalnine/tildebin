"""Tests for lsm_restriction_audit script."""

import pytest

from boxctl.core.output import Output


class TestLsmRestrictionAudit:
    """Tests for lsm_restriction_audit."""

    def test_no_lsm_file(self, mock_context):
        """Returns exit 2 when /sys/kernel/security/lsm does not exist."""
        from scripts.baremetal import lsm_restriction_audit

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = lsm_restriction_audit.run([], output, ctx)

        assert exit_code == 2

    def test_landlock_enabled(self, mock_context):
        """Returns exit 0 when landlock is in the LSM list."""
        from scripts.baremetal import lsm_restriction_audit

        ctx = mock_context(
            file_contents={
                "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor,bpf",
                "/proc/sys/kernel/io_uring_disabled": "2",
            }
        )
        output = Output()

        exit_code = lsm_restriction_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["landlock_enabled"] is True

    def test_landlock_missing(self, mock_context):
        """Returns exit 1 with warning when landlock is not in the LSM list."""
        from scripts.baremetal import lsm_restriction_audit

        ctx = mock_context(
            file_contents={
                "/sys/kernel/security/lsm": "lockdown,capability,yama,apparmor,bpf",
                "/proc/sys/kernel/io_uring_disabled": "2",
            }
        )
        output = Output()

        exit_code = lsm_restriction_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["landlock_enabled"] is False
        assert "Landlock LSM is not active" in output.data["warnings"]

    def test_io_uring_unrestricted(self, mock_context):
        """Returns exit 1 with warning when io_uring_disabled is 0."""
        from scripts.baremetal import lsm_restriction_audit

        ctx = mock_context(
            file_contents={
                "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor,bpf",
                "/proc/sys/kernel/io_uring_disabled": "0",
            }
        )
        output = Output()

        exit_code = lsm_restriction_audit.run([], output, ctx)

        assert exit_code == 1
        assert "io_uring is unrestricted" in str(output.data["warnings"])

    def test_io_uring_disabled(self, mock_context):
        """Returns exit 0 when io_uring_disabled is 2 (fully disabled)."""
        from scripts.baremetal import lsm_restriction_audit

        ctx = mock_context(
            file_contents={
                "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor,bpf",
                "/proc/sys/kernel/io_uring_disabled": "2",
            }
        )
        output = Output()

        exit_code = lsm_restriction_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["io_uring"]["status"] == "fully_disabled"
        assert output.data["io_uring"]["disabled"] == 2

    def test_no_io_uring_file(self, mock_context):
        """Returns exit 0 when io_uring_disabled file does not exist (older kernel)."""
        from scripts.baremetal import lsm_restriction_audit

        ctx = mock_context(
            file_contents={
                "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor,bpf",
            }
        )
        output = Output()

        exit_code = lsm_restriction_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["io_uring"] is None

    def test_json_output(self, mock_context):
        """Verify JSON output contains lsm_list and io_uring settings."""
        from scripts.baremetal import lsm_restriction_audit

        ctx = mock_context(
            file_contents={
                "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor,bpf",
                "/proc/sys/kernel/io_uring_disabled": "1",
                "/proc/sys/kernel/io_uring_group": "1000",
            }
        )
        output = Output()

        exit_code = lsm_restriction_audit.run(["--format", "json"], output, ctx)

        assert exit_code == 0
        assert "landlock" in output.data["lsm_list"]
        assert output.data["landlock_enabled"] is True
        assert output.data["io_uring"]["disabled"] == 1
        assert output.data["io_uring"]["group"] == 1000
        assert output.data["io_uring"]["status"] == "unprivileged_disabled"
