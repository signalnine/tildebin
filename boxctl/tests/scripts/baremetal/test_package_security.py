"""Tests for package_security script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def apt_security_updates(fixtures_dir):
    """Load apt security updates output."""
    return (fixtures_dir / "security" / "apt_list_upgradable_security.txt").read_text()


@pytest.fixture
def apt_no_updates(fixtures_dir):
    """Load apt no updates output."""
    return (fixtures_dir / "security" / "apt_list_upgradable_none.txt").read_text()


@pytest.fixture
def dnf_security_updates(fixtures_dir):
    """Load dnf security updates output."""
    return (fixtures_dir / "security" / "dnf_updateinfo_security.txt").read_text()


@pytest.fixture
def dnf_no_updates(fixtures_dir):
    """Load dnf no updates output."""
    return (fixtures_dir / "security" / "dnf_updateinfo_none.txt").read_text()


class TestPackageSecurity:
    """Tests for package_security script."""

    def test_unknown_package_manager_returns_error(self, mock_context):
        """Returns 2 when package manager cannot be detected."""
        from scripts.baremetal import package_security

        ctx = mock_context(
            tools_available=[],
            file_contents={},  # No apt, dnf, or yum binaries
        )
        output = Output()

        exit_code = package_security.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_apt_no_security_updates(self, mock_context, apt_no_updates):
        """Returns 0 when no apt security updates pending."""
        from scripts.baremetal import package_security

        ctx = mock_context(
            tools_available=["apt"],
            file_contents={
                "/usr/bin/apt": "",
            },
            command_outputs={
                ("apt", "list", "--upgradable"): apt_no_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "apt"], output, ctx)

        assert exit_code == 0
        assert output.data["total_updates"] == 0
        assert output.data["package_manager"] == "apt"

    def test_apt_security_updates_found(self, mock_context, apt_security_updates):
        """Returns 1 when apt security updates are pending."""
        from scripts.baremetal import package_security

        ctx = mock_context(
            tools_available=["apt"],
            file_contents={
                "/usr/bin/apt": "",
            },
            command_outputs={
                ("apt", "list", "--upgradable"): apt_security_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "apt"], output, ctx)

        assert exit_code == 1
        assert output.data["total_updates"] == 4
        assert output.data["package_manager"] == "apt"

    def test_dnf_security_updates_found(self, mock_context, dnf_security_updates):
        """Returns 1 when dnf security updates are pending."""
        from scripts.baremetal import package_security

        ctx = mock_context(
            tools_available=["dnf"],
            file_contents={
                "/usr/bin/dnf": "",
            },
            command_outputs={
                ("dnf", "updateinfo", "list", "security", "--available", "-q"): dnf_security_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "dnf"], output, ctx)

        assert exit_code == 1
        assert output.data["total_updates"] == 3
        assert output.data["package_manager"] == "dnf"

    def test_dnf_no_security_updates(self, mock_context, dnf_no_updates):
        """Returns 0 when no dnf security updates pending."""
        from scripts.baremetal import package_security

        ctx = mock_context(
            tools_available=["dnf"],
            file_contents={
                "/usr/bin/dnf": "",
            },
            command_outputs={
                ("dnf", "updateinfo", "list", "security", "--available", "-q"): dnf_no_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "dnf"], output, ctx)

        assert exit_code == 0
        assert output.data["total_updates"] == 0

    def test_critical_only_flag(self, mock_context, dnf_security_updates):
        """--critical-only only alerts for critical/important updates."""
        from scripts.baremetal import package_security

        # dnf_security_updates has Critical, Important, and Moderate
        ctx = mock_context(
            tools_available=["dnf"],
            file_contents={
                "/usr/bin/dnf": "",
            },
            command_outputs={
                ("dnf", "updateinfo", "list", "security", "--available", "-q"): dnf_security_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "dnf", "--critical-only"], output, ctx)

        # Should return 1 because there are critical/important updates
        assert exit_code == 1
        assert output.data["has_critical"] is True

    def test_critical_only_no_critical(self, mock_context):
        """--critical-only returns 0 when no critical updates."""
        from scripts.baremetal import package_security

        # Only low severity updates
        low_updates = "RHSA-2025:0126 Low/Sec. vim-common-2:8.2.4857-1.el9.x86_64\n"

        ctx = mock_context(
            tools_available=["dnf"],
            file_contents={
                "/usr/bin/dnf": "",
            },
            command_outputs={
                ("dnf", "updateinfo", "list", "security", "--available", "-q"): low_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "dnf", "--critical-only"], output, ctx)

        # Should return 0 because no critical/important
        assert exit_code == 0
        assert output.data["total_updates"] == 1
        assert output.data["has_critical"] is False

    def test_verbose_includes_packages(self, mock_context, apt_security_updates):
        """Verbose mode includes package details."""
        from scripts.baremetal import package_security

        ctx = mock_context(
            tools_available=["apt"],
            file_contents={
                "/usr/bin/apt": "",
            },
            command_outputs={
                ("apt", "list", "--upgradable"): apt_security_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "apt", "--verbose"], output, ctx)

        assert exit_code == 1
        assert len(output.data["updates"]) == 4
        assert output.data["updates"][0]["package"] == "libssl3"

    def test_severity_categorization(self, mock_context, dnf_security_updates):
        """Severity is correctly categorized."""
        from scripts.baremetal import package_security

        ctx = mock_context(
            tools_available=["dnf"],
            file_contents={
                "/usr/bin/dnf": "",
            },
            command_outputs={
                ("dnf", "updateinfo", "list", "security", "--available", "-q"): dnf_security_updates,
            },
        )
        output = Output()

        exit_code = package_security.run(["--package-manager", "dnf"], output, ctx)

        categories = output.data["categories"]
        # Based on fixture: 1 Critical, 1 Important, 1 Moderate
        assert categories["critical"] >= 1
        assert categories["important"] >= 1
        assert categories["moderate"] >= 1
