"""Tests for efi_boot_audit script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def efibootmgr_healthy(fixtures_dir):
    """Load healthy efibootmgr output."""
    return (fixtures_dir / "boot" / "efibootmgr_healthy.txt").read_text()


@pytest.fixture
def efibootmgr_duplicates(fixtures_dir):
    """Load efibootmgr output with duplicate entries."""
    return (fixtures_dir / "boot" / "efibootmgr_duplicates.txt").read_text()


@pytest.fixture
def efibootmgr_missing_entry(fixtures_dir):
    """Load efibootmgr output with missing boot order entry."""
    return (fixtures_dir / "boot" / "efibootmgr_missing_entry.txt").read_text()


@pytest.fixture
def efibootmgr_no_entries(fixtures_dir):
    """Load efibootmgr output with no entries."""
    return (fixtures_dir / "boot" / "efibootmgr_no_entries.txt").read_text()


class TestEfiBootAudit:
    """Tests for efi_boot_audit script."""

    def test_not_efi_system_returns_error(self, mock_context):
        """Returns exit code 2 when not an EFI system."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = efi_boot_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("efi" in e.lower() for e in output.errors)

    def test_missing_efibootmgr_returns_error(self, mock_context):
        """Returns exit code 2 when efibootmgr not available."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(
            file_contents={"/sys/firmware/efi": ""},
            tools_available=[],
        )
        output = Output()

        exit_code = efi_boot_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("efibootmgr" in e.lower() for e in output.errors)

    def test_healthy_config_returns_zero(self, mock_context, efibootmgr_healthy):
        """Returns 0 when EFI config is healthy."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(
            tools_available=["efibootmgr"],
            file_contents={"/sys/firmware/efi": ""},
            command_outputs={
                ("efibootmgr", "-v"): efibootmgr_healthy,
            }
        )
        output = Output()

        exit_code = efi_boot_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["boot_current"] == "0001"
        assert output.data["entry_count"] == 3

    def test_duplicate_entries_detected(self, mock_context, efibootmgr_duplicates):
        """Detects duplicate boot entry labels."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(
            tools_available=["efibootmgr"],
            file_contents={"/sys/firmware/efi": ""},
            command_outputs={
                ("efibootmgr", "-v"): efibootmgr_duplicates,
            }
        )
        output = Output()

        exit_code = efi_boot_audit.run([], output, ctx)

        assert exit_code == 1
        duplicate_issues = [
            i for i in output.data["issues"]
            if "duplicate" in i["message"].lower()
        ]
        assert len(duplicate_issues) > 0

    def test_missing_boot_order_entry_detected(self, mock_context, efibootmgr_missing_entry):
        """Detects boot order referencing non-existent entry."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(
            tools_available=["efibootmgr"],
            file_contents={"/sys/firmware/efi": ""},
            command_outputs={
                ("efibootmgr", "-v"): efibootmgr_missing_entry,
            }
        )
        output = Output()

        exit_code = efi_boot_audit.run([], output, ctx)

        assert exit_code == 1
        missing_issues = [
            i for i in output.data["issues"]
            if "non-existent" in i["message"].lower()
        ]
        assert len(missing_issues) > 0

    def test_no_entries_critical(self, mock_context, efibootmgr_no_entries):
        """Detects no EFI boot entries as critical."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(
            tools_available=["efibootmgr"],
            file_contents={"/sys/firmware/efi": ""},
            command_outputs={
                ("efibootmgr", "-v"): efibootmgr_no_entries,
            }
        )
        output = Output()

        exit_code = efi_boot_audit.run([], output, ctx)

        assert exit_code == 1
        critical_issues = [
            i for i in output.data["issues"]
            if i["severity"] == "CRITICAL"
        ]
        assert len(critical_issues) > 0

    def test_timeout_zero_info(self, mock_context, efibootmgr_duplicates):
        """Reports timeout=0 as info issue."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(
            tools_available=["efibootmgr"],
            file_contents={"/sys/firmware/efi": ""},
            command_outputs={
                ("efibootmgr", "-v"): efibootmgr_duplicates,
            }
        )
        output = Output()

        exit_code = efi_boot_audit.run([], output, ctx)

        timeout_issues = [
            i for i in output.data["issues"]
            if i["severity"] == "INFO" and "timeout" in i["message"].lower()
        ]
        assert len(timeout_issues) > 0

    def test_verbose_includes_entries(self, mock_context, efibootmgr_healthy):
        """--verbose includes full entry details."""
        from scripts.baremetal import efi_boot_audit

        ctx = mock_context(
            tools_available=["efibootmgr"],
            file_contents={"/sys/firmware/efi": ""},
            command_outputs={
                ("efibootmgr", "-v"): efibootmgr_healthy,
            }
        )
        output = Output()

        exit_code = efi_boot_audit.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert output.data["entries"] is not None
        assert "0001" in output.data["entries"]
