"""Tests for grub_config_audit script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def grub_default_healthy(fixtures_dir):
    """Load healthy GRUB defaults."""
    return (fixtures_dir / "boot" / "grub_default_healthy.txt").read_text()


@pytest.fixture
def grub_default_insecure(fixtures_dir):
    """Load insecure GRUB defaults."""
    return (fixtures_dir / "boot" / "grub_default_insecure.txt").read_text()


@pytest.fixture
def grub_cfg_healthy(fixtures_dir):
    """Load healthy GRUB config."""
    return (fixtures_dir / "boot" / "grub_cfg_healthy.txt").read_text()


@pytest.fixture
def grub_user_cfg_password(fixtures_dir):
    """Load GRUB password config."""
    return (fixtures_dir / "boot" / "grub_user_cfg_password.txt").read_text()


class TestGrubConfigAudit:
    """Tests for grub_config_audit script."""

    def test_no_boot_returns_error(self, mock_context):
        """Returns exit code 2 when /boot not found."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_healthy_config_with_password(
        self, mock_context, grub_default_healthy, grub_cfg_healthy, grub_user_cfg_password
    ):
        """Returns 0 when GRUB is properly configured with password."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(
            file_contents={
                "/boot": "",  # Directory exists marker
                "/boot/grub/grub.cfg": grub_cfg_healthy,
                "/etc/default/grub": grub_default_healthy,
                "/boot/grub/user.cfg": grub_user_cfg_password,
            }
        )
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["password_protected"] is True

    def test_no_password_protection_warns(
        self, mock_context, grub_default_healthy, grub_cfg_healthy
    ):
        """Warns when GRUB password protection is not enabled."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(
            file_contents={
                "/boot": "",
                "/boot/grub/grub.cfg": grub_cfg_healthy,
                "/etc/default/grub": grub_default_healthy,
            }
        )
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["password_protected"] is False
        password_issues = [i for i in output.data["issues"] if "password" in i["message"].lower()]
        assert len(password_issues) > 0

    def test_mitigations_off_critical(
        self, mock_context, grub_default_insecure, grub_cfg_healthy
    ):
        """Detects mitigations=off as critical issue."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(
            file_contents={
                "/boot": "",
                "/boot/grub/grub.cfg": grub_cfg_healthy,
                "/etc/default/grub": grub_default_insecure,
            }
        )
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["security"]["mitigations_off"] is True
        critical_issues = [i for i in output.data["issues"] if i["severity"] == "CRITICAL"]
        assert len(critical_issues) > 0

    def test_nokaslr_detected(
        self, mock_context, grub_default_insecure, grub_cfg_healthy
    ):
        """Detects nokaslr as security issue."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(
            file_contents={
                "/boot": "",
                "/boot/grub/grub.cfg": grub_cfg_healthy,
                "/etc/default/grub": grub_default_insecure,
            }
        )
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["security"]["kaslr_disabled"] is True

    def test_selinux_disabled_detected(
        self, mock_context, grub_default_insecure, grub_cfg_healthy
    ):
        """Detects SELinux disabled via boot parameters."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(
            file_contents={
                "/boot": "",
                "/boot/grub/grub.cfg": grub_cfg_healthy,
                "/etc/default/grub": grub_default_insecure,
            }
        )
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["security"]["selinux_status"] == "disabled"

    def test_timeout_zero_reported(
        self, mock_context, grub_default_insecure, grub_cfg_healthy
    ):
        """Reports timeout=0 as info issue."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(
            file_contents={
                "/boot": "",
                "/boot/grub/grub.cfg": grub_cfg_healthy,
                "/etc/default/grub": grub_default_insecure,
            }
        )
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        # Should have an INFO issue about timeout
        timeout_issues = [
            i for i in output.data["issues"]
            if i["severity"] == "INFO" and "timeout" in i["message"].lower()
        ]
        assert len(timeout_issues) > 0

    def test_iommu_enabled_detected(
        self, mock_context, grub_default_healthy, grub_cfg_healthy
    ):
        """Detects IOMMU enabled in kernel cmdline."""
        from scripts.baremetal import grub_config_audit

        ctx = mock_context(
            file_contents={
                "/boot": "",
                "/boot/grub/grub.cfg": grub_cfg_healthy,
                "/etc/default/grub": grub_default_healthy,
            }
        )
        output = Output()

        exit_code = grub_config_audit.run([], output, ctx)

        assert output.data["security"]["iommu_enabled"] is True
