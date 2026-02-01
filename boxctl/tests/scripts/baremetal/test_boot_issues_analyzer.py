"""Tests for boot_issues_analyzer script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def journalctl_boots(fixtures_dir):
    """Load boot list output."""
    return (fixtures_dir / "boot" / "journalctl_list_boots_healthy.txt").read_text()


@pytest.fixture
def boot_healthy(fixtures_dir):
    """Load healthy boot log."""
    return (fixtures_dir / "boot" / "journalctl_boot_healthy.txt").read_text()


@pytest.fixture
def boot_kernel_panic(fixtures_dir):
    """Load boot log with kernel panic."""
    return (fixtures_dir / "boot" / "journalctl_boot_kernel_panic.txt").read_text()


@pytest.fixture
def boot_oom(fixtures_dir):
    """Load boot log with OOM kills."""
    return (fixtures_dir / "boot" / "journalctl_boot_oom.txt").read_text()


@pytest.fixture
def boot_emergency(fixtures_dir):
    """Load boot log with emergency mode."""
    return (fixtures_dir / "boot" / "journalctl_boot_emergency.txt").read_text()


@pytest.fixture
def boot_failed_units(fixtures_dir):
    """Load boot log with failed units."""
    return (fixtures_dir / "boot" / "journalctl_boot_failed_units.txt").read_text()


@pytest.fixture
def boot_hw_error(fixtures_dir):
    """Load boot log with hardware errors."""
    return (fixtures_dir / "boot" / "journalctl_boot_hw_error.txt").read_text()


class TestBootIssuesAnalyzer:
    """Tests for boot_issues_analyzer script."""

    def test_missing_journalctl_returns_error(self, mock_context):
        """Returns exit code 2 when journalctl not available."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = boot_issues_analyzer.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("journalctl" in e.lower() for e in output.errors)

    def test_healthy_boots_returns_zero(self, mock_context, journalctl_boots, boot_healthy):
        """Returns 0 when no issues detected in boots."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--list-boots", "--no-pager"): journalctl_boots,
                ("journalctl", "-b", "a1b2c3d4e5f6", "--no-pager", "-o", "short-iso"): boot_healthy,
                ("journalctl", "-b", "b2c3d4e5f6a1", "--no-pager", "-o", "short-iso"): boot_healthy,
                ("journalctl", "-b", "c3d4e5f6a1b2", "--no-pager", "-o", "short-iso"): boot_healthy,
            }
        )
        output = Output()

        exit_code = boot_issues_analyzer.run(["--boots", "3"], output, ctx)

        assert exit_code == 0
        assert output.data["total_issues"] == 0
        assert output.data["boots_analyzed"] == 3

    def test_kernel_panic_detected(self, mock_context, journalctl_boots, boot_kernel_panic):
        """Detects kernel panic issues."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--list-boots", "--no-pager"): journalctl_boots,
                ("journalctl", "-b", "a1b2c3d4e5f6", "--no-pager", "-o", "short-iso"): boot_kernel_panic,
            }
        )
        output = Output()

        exit_code = boot_issues_analyzer.run(["--boots", "1"], output, ctx)

        assert exit_code == 1
        assert output.data["total_issues"] > 0
        boot_result = output.data["boots"][0]
        kernel_issues = [i for i in boot_result["issues"] if i["type"] == "kernel_error"]
        assert len(kernel_issues) > 0

    def test_oom_kills_detected(self, mock_context, journalctl_boots, boot_oom):
        """Detects OOM kill issues."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--list-boots", "--no-pager"): journalctl_boots,
                ("journalctl", "-b", "a1b2c3d4e5f6", "--no-pager", "-o", "short-iso"): boot_oom,
            }
        )
        output = Output()

        exit_code = boot_issues_analyzer.run(["--boots", "1"], output, ctx)

        assert exit_code == 1
        boot_result = output.data["boots"][0]
        oom_issues = [i for i in boot_result["issues"] if i["type"] == "oom_kill"]
        assert len(oom_issues) > 0

    def test_emergency_mode_detected(self, mock_context, journalctl_boots, boot_emergency):
        """Detects emergency mode entry."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--list-boots", "--no-pager"): journalctl_boots,
                ("journalctl", "-b", "a1b2c3d4e5f6", "--no-pager", "-o", "short-iso"): boot_emergency,
            }
        )
        output = Output()

        exit_code = boot_issues_analyzer.run(["--boots", "1"], output, ctx)

        assert exit_code == 1
        boot_result = output.data["boots"][0]
        emergency_issues = [i for i in boot_result["issues"] if i["type"] == "emergency_mode"]
        assert len(emergency_issues) > 0
        assert boot_result["critical_count"] > 0

    def test_failed_units_detected(self, mock_context, journalctl_boots, boot_failed_units):
        """Detects failed systemd units."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--list-boots", "--no-pager"): journalctl_boots,
                ("journalctl", "-b", "a1b2c3d4e5f6", "--no-pager", "-o", "short-iso"): boot_failed_units,
            }
        )
        output = Output()

        exit_code = boot_issues_analyzer.run(["--boots", "1"], output, ctx)

        assert exit_code == 1
        boot_result = output.data["boots"][0]
        unit_issues = [i for i in boot_result["issues"] if i["type"] == "failed_unit"]
        assert len(unit_issues) > 0

    def test_hardware_errors_detected(self, mock_context, journalctl_boots, boot_hw_error):
        """Detects hardware errors."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--list-boots", "--no-pager"): journalctl_boots,
                ("journalctl", "-b", "a1b2c3d4e5f6", "--no-pager", "-o", "short-iso"): boot_hw_error,
            }
        )
        output = Output()

        exit_code = boot_issues_analyzer.run(["--boots", "1"], output, ctx)

        assert exit_code == 1
        boot_result = output.data["boots"][0]
        hw_issues = [i for i in boot_result["issues"] if i["type"] == "hardware_error"]
        assert len(hw_issues) > 0

    def test_invalid_check_returns_error(self, mock_context, journalctl_boots):
        """Returns error for invalid check type."""
        from scripts.baremetal import boot_issues_analyzer

        ctx = mock_context(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--list-boots", "--no-pager"): journalctl_boots,
            }
        )
        output = Output()

        exit_code = boot_issues_analyzer.run(["--checks", "invalid_check"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
