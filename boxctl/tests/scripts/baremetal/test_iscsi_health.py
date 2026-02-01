"""Tests for iscsi_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def sessions_healthy(fixtures_dir):
    """Load healthy sessions output."""
    return (fixtures_dir / "storage" / "iscsiadm_sessions_healthy.txt").read_text()


@pytest.fixture
def sessions_none(fixtures_dir):
    """Load empty sessions output."""
    return (fixtures_dir / "storage" / "iscsiadm_sessions_none.txt").read_text()


@pytest.fixture
def session_details_healthy(fixtures_dir):
    """Load healthy session details."""
    return (fixtures_dir / "storage" / "iscsiadm_session_details_healthy.txt").read_text()


@pytest.fixture
def session_details_degraded(fixtures_dir):
    """Load degraded session details."""
    return (fixtures_dir / "storage" / "iscsiadm_session_details_degraded.txt").read_text()


@pytest.fixture
def session_stats_healthy(fixtures_dir):
    """Load healthy session stats."""
    return (fixtures_dir / "storage" / "iscsiadm_session_stats_healthy.txt").read_text()


@pytest.fixture
def session_stats_errors(fixtures_dir):
    """Load session stats with errors."""
    return (fixtures_dir / "storage" / "iscsiadm_session_stats_errors.txt").read_text()


class TestIscsiHealth:
    """Tests for iscsi_health script."""

    def test_missing_iscsiadm_returns_error(self, mock_context):
        """Returns exit code 2 when iscsiadm not available."""
        from scripts.baremetal import iscsi_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = iscsi_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("iscsiadm" in e.lower() for e in output.errors)

    def test_no_sessions_returns_healthy(self, mock_context, sessions_none):
        """Returns 0 when no iSCSI sessions exist."""
        from scripts.baremetal import iscsi_health

        ctx = mock_context(
            tools_available=["iscsiadm"],
            command_outputs={
                ("iscsiadm", "-m", "session"): sessions_none,
            }
        )
        output = Output()

        exit_code = iscsi_health.run([], output, ctx)

        assert exit_code == 0
        assert "sessions" in output.data
        assert len(output.data["sessions"]) == 0

    def test_healthy_sessions_returns_zero(
        self,
        mock_context,
        sessions_healthy,
        session_details_healthy,
        session_stats_healthy,
    ):
        """Returns 0 when all sessions are healthy."""
        from scripts.baremetal import iscsi_health

        ctx = mock_context(
            tools_available=["iscsiadm"],
            command_outputs={
                ("iscsiadm", "-m", "session"): sessions_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-P", "3"): session_details_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-s"): session_stats_healthy,
                ("iscsiadm", "-m", "session", "-r", "2", "-P", "3"): session_details_healthy,
                ("iscsiadm", "-m", "session", "-r", "2", "-s"): session_stats_healthy,
            }
        )
        output = Output()

        exit_code = iscsi_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["sessions"]) == 2
        assert len(output.data["issues"]) == 0

    def test_degraded_session_returns_one(
        self,
        mock_context,
        sessions_healthy,
        session_details_degraded,
        session_stats_healthy,
    ):
        """Returns 1 when a session is degraded."""
        from scripts.baremetal import iscsi_health

        ctx = mock_context(
            tools_available=["iscsiadm"],
            command_outputs={
                ("iscsiadm", "-m", "session"): sessions_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-P", "3"): session_details_degraded,
                ("iscsiadm", "-m", "session", "-r", "1", "-s"): session_stats_healthy,
                ("iscsiadm", "-m", "session", "-r", "2", "-P", "3"): session_details_degraded,
                ("iscsiadm", "-m", "session", "-r", "2", "-s"): session_stats_healthy,
            }
        )
        output = Output()

        exit_code = iscsi_health.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["issues"]) > 0

    def test_session_errors_returns_one(
        self,
        mock_context,
        sessions_healthy,
        session_details_healthy,
        session_stats_errors,
        session_stats_healthy,
    ):
        """Returns 1 when session has timeout/digest errors."""
        from scripts.baremetal import iscsi_health

        ctx = mock_context(
            tools_available=["iscsiadm"],
            command_outputs={
                ("iscsiadm", "-m", "session"): sessions_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-P", "3"): session_details_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-s"): session_stats_errors,
                ("iscsiadm", "-m", "session", "-r", "2", "-P", "3"): session_details_healthy,
                ("iscsiadm", "-m", "session", "-r", "2", "-s"): session_stats_healthy,
            }
        )
        output = Output()

        exit_code = iscsi_health.run([], output, ctx)

        assert exit_code == 1
        assert any("timeout" in i["message"].lower() or "digest" in i["message"].lower()
                   for i in output.data["issues"])

    def test_device_not_running_creates_issue(
        self,
        mock_context,
        sessions_healthy,
        session_details_degraded,
        session_stats_healthy,
    ):
        """Creates issue when attached device is not running."""
        from scripts.baremetal import iscsi_health

        ctx = mock_context(
            tools_available=["iscsiadm"],
            command_outputs={
                ("iscsiadm", "-m", "session"): sessions_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-P", "3"): session_details_degraded,
                ("iscsiadm", "-m", "session", "-r", "1", "-s"): session_stats_healthy,
                ("iscsiadm", "-m", "session", "-r", "2", "-P", "3"): session_details_degraded,
                ("iscsiadm", "-m", "session", "-r", "2", "-s"): session_stats_healthy,
            }
        )
        output = Output()

        exit_code = iscsi_health.run([], output, ctx)

        assert exit_code == 1
        # Check for device state issues
        assert any("transport-offline" in i["message"].lower() or "device" in i["message"].lower()
                   for i in output.data["issues"])

    def test_verbose_includes_stats(
        self,
        mock_context,
        sessions_healthy,
        session_details_healthy,
        session_stats_healthy,
    ):
        """Verbose mode includes statistics in output."""
        from scripts.baremetal import iscsi_health

        ctx = mock_context(
            tools_available=["iscsiadm"],
            command_outputs={
                ("iscsiadm", "-m", "session"): sessions_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-P", "3"): session_details_healthy,
                ("iscsiadm", "-m", "session", "-r", "1", "-s"): session_stats_healthy,
                ("iscsiadm", "-m", "session", "-r", "2", "-P", "3"): session_details_healthy,
                ("iscsiadm", "-m", "session", "-r", "2", "-s"): session_stats_healthy,
            }
        )
        output = Output()

        exit_code = iscsi_health.run(["-v"], output, ctx)

        assert exit_code == 0
        assert "stats" in output.data["sessions"][0]
