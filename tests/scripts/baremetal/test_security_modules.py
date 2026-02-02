"""Tests for security_modules script."""

import pytest

from boxctl.core.output import Output


class TestSecurityModules:
    """Tests for security_modules script."""

    def test_no_lsm_available_returns_error(self, mock_context):
        """Returns exit code 2 when no LSM is available."""
        from scripts.baremetal import security_modules

        ctx = mock_context(
            tools_available=[],
            command_outputs={
                ("which", "getenforce"): "",
                ("which", "aa-status"): "",
            }
        )

        # Monkeypatch os.path.exists to return False for LSM paths
        import os
        original_exists = os.path.exists

        def mock_exists(path):
            if path in ['/sys/fs/selinux', '/sys/module/apparmor']:
                return False
            return original_exists(path)

        import scripts.baremetal.security_modules as sm
        original_se = sm.check_selinux_available
        original_aa = sm.check_apparmor_available
        sm.check_selinux_available = lambda ctx: False
        sm.check_apparmor_available = lambda ctx: False

        output = Output()

        try:
            exit_code = security_modules.run([], output, ctx)
            assert exit_code == 2
            assert len(output.errors) > 0
        finally:
            sm.check_selinux_available = original_se
            sm.check_apparmor_available = original_aa

    def test_invalid_hours_argument(self, mock_context):
        """Returns exit code 2 for invalid --hours."""
        from scripts.baremetal import security_modules

        ctx = mock_context()
        output = Output()

        exit_code = security_modules.run(["--hours", "0"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_limit_argument(self, mock_context):
        """Returns exit code 2 for invalid --limit."""
        from scripts.baremetal import security_modules

        ctx = mock_context()
        output = Output()

        exit_code = security_modules.run(["--limit", "0"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_selinux_enforcing(self, mock_context, monkeypatch):
        """Returns 0 for SELinux in enforcing mode."""
        from scripts.baremetal import security_modules

        ctx = mock_context(
            tools_available=["getenforce", "sestatus", "getsebool", "tail", "dmesg"],
            command_outputs={
                ("getenforce",): "Enforcing\n",
                ("sestatus",): "SELinux status: enabled\nPolicy MLS status: disabled\n",
                ("getsebool", "-a"): "",
                ("tail", "-n", "1000", "/var/log/audit/audit.log"): "",
                ("dmesg", "--time-format=iso"): "",
            }
        )

        monkeypatch.setattr(security_modules, "check_selinux_available", lambda c: True)
        monkeypatch.setattr(security_modules, "check_apparmor_available", lambda c: False)

        output = Output()

        exit_code = security_modules.run([], output, ctx)

        assert exit_code == 0
        assert output.data["selinux_available"] is True
        assert output.data["selinux"]["mode"] == "enforcing"

    def test_selinux_permissive_warning(self, mock_context, monkeypatch):
        """Returns 1 for SELinux in permissive mode."""
        from scripts.baremetal import security_modules

        ctx = mock_context(
            tools_available=["getenforce", "sestatus", "getsebool", "tail", "dmesg"],
            command_outputs={
                ("getenforce",): "Permissive\n",
                ("sestatus",): "SELinux status: enabled\n",
                ("getsebool", "-a"): "",
                ("tail", "-n", "1000", "/var/log/audit/audit.log"): "",
                ("dmesg", "--time-format=iso"): "",
            }
        )

        monkeypatch.setattr(security_modules, "check_selinux_available", lambda c: True)
        monkeypatch.setattr(security_modules, "check_apparmor_available", lambda c: False)

        output = Output()

        exit_code = security_modules.run([], output, ctx)

        assert exit_code == 1
        assert any(i["type"] == "selinux_permissive" for i in output.data["issues"])

    def test_apparmor_enabled(self, mock_context, monkeypatch):
        """Returns 0 for AppArmor enabled."""
        from scripts.baremetal import security_modules
        import json

        aa_json = json.dumps({
            "profiles": {
                "/usr/bin/foo": "enforce",
                "/usr/bin/bar": "enforce",
            },
            "processes": {}
        })

        ctx = mock_context(
            tools_available=["aa-status", "tail", "dmesg"],
            command_outputs={
                ("aa-status", "--json"): aa_json,
                ("aa-status",): "2 profiles are loaded.\n2 profiles are in enforce mode.\n",
                ("tail", "-n", "1000", "/var/log/audit/audit.log"): "",
                ("dmesg", "--time-format=iso"): "",
            }
        )

        monkeypatch.setattr(security_modules, "check_selinux_available", lambda c: False)
        monkeypatch.setattr(security_modules, "check_apparmor_available", lambda c: True)
        monkeypatch.setattr("os.path.exists", lambda p: p == '/sys/module/apparmor')

        output = Output()

        exit_code = security_modules.run([], output, ctx)

        assert exit_code == 0
        assert output.data["apparmor_available"] is True
        assert output.data["apparmor"]["enabled"] is True

    def test_parse_selinux_denial(self, mock_context):
        """Test parsing SELinux denial messages."""
        from scripts.baremetal.security_modules import parse_selinux_denial

        line = 'avc:  denied  { read } for  pid=1234 comm="myapp" name="file" scontext=user_u:user_r:user_t tcontext=system_u:object_r:etc_t tclass=file'

        denial = parse_selinux_denial(line)

        assert denial is not None
        assert denial["type"] == "selinux"
        assert denial["permission"] == "read"
        assert denial["command"] == "myapp"
        assert "scontext" in line  # source context present

    def test_parse_apparmor_denial(self, mock_context):
        """Test parsing AppArmor denial messages."""
        from scripts.baremetal.security_modules import parse_apparmor_denial

        line = 'apparmor="DENIED" operation="open" profile="/usr/bin/myapp" name="/etc/passwd" comm="myapp"'

        denial = parse_apparmor_denial(line)

        assert denial is not None
        assert denial["type"] == "apparmor"
        assert denial["profile"] == "/usr/bin/myapp"
        assert denial["permission"] == "open"
        assert denial["target"] == "/etc/passwd"

    def test_denials_trigger_warning(self, mock_context, monkeypatch):
        """Denials in logs trigger warning exit code."""
        from scripts.baremetal import security_modules

        ctx = mock_context(
            tools_available=["getenforce", "sestatus", "getsebool", "tail", "dmesg"],
            command_outputs={
                ("getenforce",): "Enforcing\n",
                ("sestatus",): "SELinux status: enabled\n",
                ("getsebool", "-a"): "",
                ("tail", "-n", "1000", "/var/log/audit/audit.log"): "",
                ("dmesg", "--time-format=iso"): 'avc:  denied  { read } for comm="badapp" tclass=file\n',
            }
        )

        monkeypatch.setattr(security_modules, "check_selinux_available", lambda c: True)
        monkeypatch.setattr(security_modules, "check_apparmor_available", lambda c: False)

        output = Output()

        exit_code = security_modules.run([], output, ctx)

        assert exit_code == 1
        assert output.data["denial_count"] > 0
