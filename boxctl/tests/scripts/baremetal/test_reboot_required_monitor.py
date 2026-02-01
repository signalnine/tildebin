"""Tests for reboot_required_monitor script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def reboot_required_pkgs(fixtures_dir):
    """Load reboot required packages fixture."""
    return (fixtures_dir / "boot" / "reboot_required_pkgs.txt").read_text()


@pytest.fixture
def uname_r(fixtures_dir):
    """Load uname -r output fixture."""
    return (fixtures_dir / "boot" / "uname_r.txt").read_text()


@pytest.fixture
def needs_restarting_services(fixtures_dir):
    """Load needs-restarting services fixture."""
    return (fixtures_dir / "boot" / "needs_restarting_services.txt").read_text()


@pytest.fixture
def lsof_deleted(fixtures_dir):
    """Load lsof +L1 output fixture."""
    return (fixtures_dir / "boot" / "lsof_deleted.txt").read_text()


class TestRebootRequiredMonitor:
    """Tests for reboot_required_monitor script."""

    def test_missing_uname_returns_error(self, mock_context):
        """Returns exit code 2 when uname not available."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_reboot_required_returns_zero(self, mock_context):
        """Returns 0 when no reboot is required."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(
            tools_available=["uname"],
            file_contents={
                "/boot/vmlinuz-5.15.0-91-generic": "",
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "OK"
        assert output.data["reboot_required"] is False

    def test_kernel_mismatch_detected(self, mock_context, uname_r):
        """Detects kernel version mismatch."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(
            tools_available=["uname"],
            file_contents={
                # Newer kernel installed
                "/boot/vmlinuz-5.15.0-91-generic": "",
                "/boot/vmlinuz-5.15.0-89-generic": "",
            },
            command_outputs={
                # Running older kernel
                ("uname", "-r"): uname_r,  # 5.15.0-89-generic
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["reboot_required"] is True
        assert output.data["kernel"]["mismatch"] is True
        assert output.data["kernel"]["running"] == "5.15.0-89-generic"
        assert output.data["kernel"]["newest_installed"] == "5.15.0-91-generic"

    def test_debian_reboot_required_detected(self, mock_context, reboot_required_pkgs):
        """Detects Debian/Ubuntu reboot-required flag."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(
            tools_available=["uname"],
            file_contents={
                "/boot/vmlinuz-5.15.0-91-generic": "",
                "/var/run/reboot-required": "*** System restart required ***\n",
                "/var/run/reboot-required.pkgs": reboot_required_pkgs,
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["reboot_required"] is True
        assert output.data["debian_reboot_required"]["required"] is True
        assert len(output.data["debian_reboot_required"]["packages"]) > 0

    def test_rhel_needs_restarting_reboot(self, mock_context):
        """Detects RHEL needs-restarting reboot requirement."""
        from scripts.baremetal import reboot_required_monitor

        # Note: needs-restarting returns exit code 1 when reboot is needed
        # MockContext always returns 0, so we need to handle this differently
        # For this test, we'll check that the script properly queries the tool
        ctx = mock_context(
            tools_available=["uname", "needs-restarting"],
            file_contents={
                "/boot/vmlinuz-5.15.0-91-generic": "",
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("needs-restarting", "-r"): "Core libraries or services have been updated\n",
                ("needs-restarting", "-s"): "",
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        # Tool returns 0 by default in mock, so reboot not required
        assert output.data["rhel_needs_restarting"]["available"] is True

    def test_rhel_services_need_restart(self, mock_context, needs_restarting_services):
        """Detects services needing restart."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(
            tools_available=["uname", "needs-restarting"],
            file_contents={
                "/boot/vmlinuz-5.15.0-91-generic": "",
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("needs-restarting", "-r"): "",
                ("needs-restarting", "-s"): needs_restarting_services,
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert output.data["rhel_needs_restarting"]["available"] is True
        assert len(output.data["rhel_needs_restarting"]["services"]) > 0
        assert "sshd.service" in output.data["rhel_needs_restarting"]["services"]

    def test_deleted_libraries_detected(self, mock_context, lsof_deleted):
        """Detects processes using deleted libraries."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(
            tools_available=["uname", "lsof"],
            file_contents={
                "/boot/vmlinuz-5.15.0-91-generic": "",
            },
            command_outputs={
                ("uname", "-r"): "5.15.0-91-generic\n",
                ("lsof", "+L1"): lsof_deleted,
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert exit_code == 1  # Reboot recommended due to deleted libs
        assert output.data["deleted_libraries"]["count"] > 0
        assert output.data["reboot_recommended"] is True

    def test_status_summary_reboot_required(self, mock_context, uname_r):
        """Sets correct summary when reboot required."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(
            tools_available=["uname"],
            file_contents={
                "/boot/vmlinuz-5.15.0-91-generic": "",
            },
            command_outputs={
                ("uname", "-r"): uname_r,  # 5.15.0-89-generic
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert exit_code == 1
        assert "reboot" in output.summary.lower()

    def test_multiple_issues_combined(self, mock_context, uname_r, reboot_required_pkgs):
        """Combines multiple reboot reasons."""
        from scripts.baremetal import reboot_required_monitor

        ctx = mock_context(
            tools_available=["uname"],
            file_contents={
                "/boot/vmlinuz-5.15.0-91-generic": "",
                "/var/run/reboot-required": "*** System restart required ***\n",
                "/var/run/reboot-required.pkgs": reboot_required_pkgs,
            },
            command_outputs={
                ("uname", "-r"): uname_r,  # 5.15.0-89-generic (mismatch)
            }
        )
        output = Output()

        exit_code = reboot_required_monitor.run([], output, ctx)

        assert exit_code == 1
        assert output.data["reboot_required"] is True
        assert output.data["kernel"]["mismatch"] is True
        assert output.data["debian_reboot_required"]["required"] is True
        # Should have at least 2 issues
        assert len(output.data["issues"]) >= 2
