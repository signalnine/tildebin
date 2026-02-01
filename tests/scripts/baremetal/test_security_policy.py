"""Tests for security_policy script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def getenforce_enforcing(fixtures_dir):
    """Load getenforce enforcing output."""
    return (fixtures_dir / "security" / "getenforce_enforcing.txt").read_text()


@pytest.fixture
def getenforce_permissive(fixtures_dir):
    """Load getenforce permissive output."""
    return (fixtures_dir / "security" / "getenforce_permissive.txt").read_text()


@pytest.fixture
def getenforce_disabled(fixtures_dir):
    """Load getenforce disabled output."""
    return (fixtures_dir / "security" / "getenforce_disabled.txt").read_text()


@pytest.fixture
def sestatus_enforcing(fixtures_dir):
    """Load sestatus enforcing output."""
    return (fixtures_dir / "security" / "sestatus_enforcing.txt").read_text()


@pytest.fixture
def aa_status_json(fixtures_dir):
    """Load aa-status JSON output."""
    return (fixtures_dir / "security" / "aa_status_json.txt").read_text()


@pytest.fixture
def aa_status_text(fixtures_dir):
    """Load aa-status text output."""
    return (fixtures_dir / "security" / "aa_status_text.txt").read_text()


@pytest.fixture
def ausearch_denials(fixtures_dir):
    """Load ausearch denials output."""
    return (fixtures_dir / "security" / "ausearch_denials.txt").read_text()


@pytest.fixture
def ausearch_no_denials(fixtures_dir):
    """Load ausearch no denials output."""
    return (fixtures_dir / "security" / "ausearch_no_denials.txt").read_text()


class TestSecurityPolicy:
    """Tests for security_policy script."""

    def test_no_lsm_detected(self, mock_context):
        """Returns 1 when no LSM is active."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=[],
            file_contents={},  # No SELinux or AppArmor filesystems
        )
        output = Output()

        exit_code = security_policy.run([], output, ctx)

        assert exit_code == 1
        assert output.data["primary_lsm"] == "none"
        assert output.data["overall_status"] == "critical"
        assert any(i["severity"] == "critical" for i in output.data["issues"])

    def test_selinux_enforcing(self, mock_context, getenforce_enforcing, sestatus_enforcing, ausearch_no_denials):
        """Returns 0 when SELinux is enforcing."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=["getenforce", "sestatus", "ausearch"],
            file_contents={
                "/sys/fs/selinux": "",
            },
            command_outputs={
                ("getenforce",): getenforce_enforcing,
                ("sestatus",): sestatus_enforcing,
                ("ausearch", "-m", "AVC", "-ts", "recent"): ausearch_no_denials,
            },
        )
        output = Output()

        exit_code = security_policy.run([], output, ctx)

        assert exit_code == 0
        assert output.data["primary_lsm"] == "selinux"
        assert output.data["selinux"]["mode"] == "enforcing"
        assert output.data["overall_status"] == "healthy"

    def test_selinux_permissive(self, mock_context, getenforce_permissive, ausearch_no_denials):
        """Returns 1 when SELinux is permissive."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=["getenforce", "ausearch"],
            file_contents={
                "/sys/fs/selinux": "",
            },
            command_outputs={
                ("getenforce",): getenforce_permissive,
                ("ausearch", "-m", "AVC", "-ts", "recent"): ausearch_no_denials,
            },
        )
        output = Output()

        exit_code = security_policy.run([], output, ctx)

        assert exit_code == 1
        assert output.data["selinux"]["mode"] == "permissive"
        assert output.data["overall_status"] == "warning"

    def test_selinux_disabled(self, mock_context, getenforce_disabled):
        """Returns 1 when SELinux is disabled."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=["getenforce"],
            file_contents={
                "/sys/fs/selinux": "",
            },
            command_outputs={
                ("getenforce",): getenforce_disabled,
            },
        )
        output = Output()

        exit_code = security_policy.run([], output, ctx)

        assert exit_code == 1
        assert output.data["selinux"]["mode"] == "disabled"
        assert output.data["overall_status"] == "critical"

    def test_selinux_with_denials(self, mock_context, getenforce_enforcing, ausearch_denials):
        """Returns 1 when SELinux has recent denials."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=["getenforce", "ausearch"],
            file_contents={
                "/sys/fs/selinux": "",
            },
            command_outputs={
                ("getenforce",): getenforce_enforcing,
                ("ausearch", "-m", "AVC", "-ts", "recent"): ausearch_denials,
            },
        )
        output = Output()

        exit_code = security_policy.run([], output, ctx)

        assert exit_code == 1
        assert output.data["selinux"]["denials_recent"] > 0
        assert output.data["overall_status"] == "warning"

    def test_apparmor_enforcing(self, mock_context, aa_status_json):
        """Returns 0 when AppArmor is enforcing."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=["aa-status"],
            file_contents={
                "/sys/kernel/security/apparmor": "",
            },
            command_outputs={
                ("aa-status", "--json"): aa_status_json,
            },
        )
        output = Output()

        exit_code = security_policy.run([], output, ctx)

        # Has enforcing profiles, but also complain mode profile
        assert output.data["primary_lsm"] == "apparmor"
        assert output.data["apparmor"]["profiles_enforcing"] >= 1

    def test_expected_mode_mismatch(self, mock_context, getenforce_permissive):
        """Returns 1 when mode doesn't match expected."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=["getenforce"],
            file_contents={
                "/sys/fs/selinux": "",
            },
            command_outputs={
                ("getenforce",): getenforce_permissive,
            },
        )
        output = Output()

        exit_code = security_policy.run(["--expected", "enforcing"], output, ctx)

        assert exit_code == 1
        assert any("mismatch" in i["message"].lower() for i in output.data["issues"])

    def test_require_lsm_flag(self, mock_context):
        """--require-lsm returns 1 when no LSM active."""
        from scripts.baremetal import security_policy

        ctx = mock_context(
            tools_available=[],
            file_contents={},
        )
        output = Output()

        exit_code = security_policy.run(["--require-lsm"], output, ctx)

        assert exit_code == 1
        assert output.data["primary_lsm"] == "none"
