"""Tests for cron_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def crontab_system_healthy(fixtures_dir):
    """Load healthy system crontab."""
    return (fixtures_dir / "services" / "crontab_system_healthy.txt").read_text()


@pytest.fixture
def crontab_user_healthy(fixtures_dir):
    """Load healthy user crontab."""
    return (fixtures_dir / "services" / "crontab_user_healthy.txt").read_text()


@pytest.fixture
def crontab_invalid_schedule(fixtures_dir):
    """Load crontab with invalid schedule."""
    return (fixtures_dir / "services" / "crontab_invalid_schedule.txt").read_text()


@pytest.fixture
def crontab_missing_user(fixtures_dir):
    """Load crontab with missing user."""
    return (fixtures_dir / "services" / "crontab_missing_user.txt").read_text()


class TestCronHealth:
    """Tests for cron_health script."""

    def test_system_crontab_healthy(self, mock_context, crontab_system_healthy):
        """Returns 0 when system crontab is healthy."""
        from scripts.baremetal import cron_health

        ctx = mock_context(
            tools_available=["id", "which"],
            file_contents={
                "/etc/crontab": crontab_system_healthy,
            },
            command_outputs={
                ("id", "root"): "uid=0(root) gid=0(root) groups=0(root)\n",
            },
        )
        output = Output()

        exit_code = cron_health.run(["--system-only"], output, ctx)

        assert exit_code == 0
        assert output.data.get("total_jobs") > 0

    def test_invalid_schedule_returns_error(self, mock_context, crontab_invalid_schedule):
        """Returns 1 when crontab has non-existent user."""
        from scripts.baremetal import cron_health

        ctx = mock_context(
            tools_available=["id", "which"],
            file_contents={
                "/etc/crontab": crontab_invalid_schedule,
            },
            command_outputs={
                ("id", "baduser123"): Exception("id: baduser123: no such user"),
                ("id", "root"): "uid=0(root) gid=0(root) groups=0(root)\n",
            },
        )
        output = Output()

        exit_code = cron_health.run(["--system-only"], output, ctx)

        assert exit_code == 1
        assert output.data.get("jobs_with_issues") > 0

    def test_missing_user_returns_error(self, mock_context, crontab_missing_user):
        """Returns 1 when crontab references non-existent user."""
        from scripts.baremetal import cron_health

        ctx = mock_context(
            tools_available=["id", "which"],
            file_contents={
                "/etc/crontab": crontab_missing_user,
            },
            command_outputs={
                ("id", "nonexistentuser"): Exception("id: nonexistentuser: no such user"),
                ("id", "root"): "uid=0(root) gid=0(root) groups=0(root)\n",
            },
        )
        output = Output()

        exit_code = cron_health.run(["--system-only"], output, ctx)

        assert exit_code == 1
        # Should have an issue for the missing user
        system_crontab = output.data.get("system_crontab", {})
        jobs = system_crontab.get("jobs", [])
        assert any(
            "does not exist" in str(j.get("issues", []))
            for j in jobs
        )

    def test_user_crontabs_checked(self, mock_context, crontab_user_healthy):
        """Checks user crontabs when not --system-only."""
        from scripts.baremetal import cron_health

        ctx = mock_context(
            tools_available=["id", "which"],
            file_contents={
                "/var/spool/cron/crontabs": "",  # Directory marker
                "/var/spool/cron/crontabs/deploy": crontab_user_healthy,
            },
            command_outputs={
                ("id", "deploy"): "uid=1000(deploy) gid=1000(deploy)\n",
            },
        )
        output = Output()

        exit_code = cron_health.run(["--user-only"], output, ctx)

        assert exit_code == 0
        user_crontabs = output.data.get("user_crontabs", [])
        assert len(user_crontabs) > 0

    def test_warn_only_filters_healthy_jobs(self, mock_context, crontab_system_healthy):
        """--warn-only filters out healthy jobs."""
        from scripts.baremetal import cron_health

        ctx = mock_context(
            tools_available=["id", "which"],
            file_contents={
                "/etc/crontab": crontab_system_healthy,
            },
            command_outputs={
                ("id", "root"): "uid=0(root) gid=0(root) groups=0(root)\n",
            },
        )
        output = Output()

        exit_code = cron_health.run(["--system-only", "--warn-only"], output, ctx)

        assert exit_code == 0
        # In warn-only mode with healthy config, jobs should be filtered
        system_crontab = output.data.get("system_crontab", {})
        jobs = system_crontab.get("jobs", [])
        # All remaining jobs should have issues (or empty if all healthy)
        assert all(j.get("severity") != "OK" for j in jobs) if jobs else True

    def test_conflicting_flags_returns_error(self, mock_context):
        """Returns 2 when both --system-only and --user-only specified."""
        from scripts.baremetal import cron_health

        ctx = mock_context(tools_available=["id", "which"])
        output = Output()

        exit_code = cron_health.run(["--system-only", "--user-only"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_crontab_returns_healthy(self, mock_context):
        """Returns 0 when no crontab files exist."""
        from scripts.baremetal import cron_health

        ctx = mock_context(
            tools_available=["id", "which"],
            file_contents={},
            command_outputs={},
        )
        output = Output()

        exit_code = cron_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data.get("total_jobs") == 0
