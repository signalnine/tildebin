"""Tests for user_login_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext, load_fixture


class TestUserLoginAudit:
    """Tests for user_login_audit."""

    def test_healthy_users(self, capsys):
        """All users with recent logins return exit code 0."""
        from scripts.baremetal.user_login_audit import run

        context = MockContext(
            tools_available=["lastlog"],
            command_outputs={
                ("lastlog",): load_fixture("users", "lastlog_healthy.txt"),
            },
            file_contents={
                "/etc/passwd": load_fixture("users", "passwd_simple.txt"),
            },
        )
        output = Output()

        # Use high dormant-days to avoid fixture dates triggering dormant detection
        result = run(["--dormant-days", "9999"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "User Account" in captured.out

    def test_dormant_account_detected(self, capsys):
        """Dormant accounts return exit code 1."""
        from scripts.baremetal.user_login_audit import run

        context = MockContext(
            tools_available=["lastlog"],
            command_outputs={
                ("lastlog",): load_fixture("users", "lastlog_dormant.txt"),
            },
            file_contents={
                "/etc/passwd": load_fixture("users", "passwd_simple.txt"),
            },
        )
        output = Output()

        # Set dormant threshold to 30 days
        result = run(["--dormant-days", "30"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Dormant" in captured.out or "dormant" in captured.out.lower()

    def test_never_logged_in_detected(self, capsys):
        """Accounts that never logged in are flagged."""
        from scripts.baremetal.user_login_audit import run

        context = MockContext(
            tools_available=["lastlog"],
            command_outputs={
                ("lastlog",): load_fixture("users", "lastlog_never.txt"),
            },
            file_contents={
                "/etc/passwd": load_fixture("users", "passwd_simple.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "never" in captured.out.lower() or "Never" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.user_login_audit import run

        context = MockContext(
            tools_available=["lastlog"],
            command_outputs={
                ("lastlog",): load_fixture("users", "lastlog_healthy.txt"),
            },
            file_contents={
                "/etc/passwd": load_fixture("users", "passwd_simple.txt"),
            },
        )
        output = Output()

        # Use high dormant-days to avoid fixture dates triggering dormant detection
        result = run(["--format", "json", "--dormant-days", "9999"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "users" in data
        assert "total_users" in data["summary"]
        assert "dormant_count" in data["summary"]

    def test_filter_by_uid(self, capsys):
        """UID filtering works correctly."""
        from scripts.baremetal.user_login_audit import run

        context = MockContext(
            tools_available=["lastlog"],
            command_outputs={
                ("lastlog",): load_fixture("users", "lastlog_healthy.txt"),
            },
            file_contents={
                "/etc/passwd": load_fixture("users", "passwd_simple.txt"),
            },
        )
        output = Output()

        # Only include UIDs >= 1001
        result = run(["--min-uid", "1001", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should exclude gabe (UID 1000), include admin (1001) and testuser (1002)
        usernames = [u["username"] for u in data["users"]]
        assert "gabe" not in usernames

    def test_include_system_accounts(self, capsys):
        """System accounts can be included."""
        from scripts.baremetal.user_login_audit import run

        context = MockContext(
            tools_available=["lastlog"],
            command_outputs={
                ("lastlog",): load_fixture("users", "lastlog_healthy.txt"),
            },
            file_contents={
                "/etc/passwd": load_fixture("users", "passwd_simple.txt"),
            },
        )
        output = Output()

        result = run(["--include-system", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should include root (UID 0)
        usernames = [u["username"] for u in data["users"]]
        assert "root" in usernames

    def test_missing_lastlog_exit_2(self, capsys):
        """Missing lastlog tool returns exit code 2."""
        from scripts.baremetal.user_login_audit import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
            file_contents={
                "/etc/passwd": load_fixture("users", "passwd_simple.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert output.errors
