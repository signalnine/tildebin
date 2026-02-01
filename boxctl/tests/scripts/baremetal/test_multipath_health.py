"""Tests for multipath_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def multipath_healthy(fixtures_dir):
    """Load healthy multipath topology output."""
    return (fixtures_dir / "storage" / "multipath_healthy.txt").read_text()


@pytest.fixture
def multipath_degraded(fixtures_dir):
    """Load degraded multipath topology output."""
    return (fixtures_dir / "storage" / "multipath_degraded.txt").read_text()


@pytest.fixture
def multipath_no_paths(fixtures_dir):
    """Load multipath with no active paths output."""
    return (fixtures_dir / "storage" / "multipath_no_paths.txt").read_text()


@pytest.fixture
def multipath_four_paths(fixtures_dir):
    """Load multipath with four paths output."""
    return (fixtures_dir / "storage" / "multipath_four_paths.txt").read_text()


@pytest.fixture
def multipathd_daemon_running(fixtures_dir):
    """Load multipathd daemon status."""
    return (fixtures_dir / "storage" / "multipathd_daemon_running.txt").read_text()


class TestMultipathHealth:
    """Tests for multipath_health script."""

    def test_missing_multipath_returns_error(self, mock_context):
        """Returns exit code 2 when multipath tools not available."""
        from scripts.baremetal import multipath_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = multipath_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("multipath" in e.lower() for e in output.errors)

    def test_multipathd_not_running(self, mock_context):
        """Returns exit code 2 when multipathd not running."""
        from scripts.baremetal import multipath_health

        ctx = mock_context(
            tools_available=["multipath", "multipathd"],
            command_outputs={
                ("multipathd", "show", "daemon"): "not running",
                ("systemctl", "is-active", "multipathd"): "inactive",
            }
        )
        output = Output()

        exit_code = multipath_health.run([], output, ctx)

        # Should exit with error because multipathd is not running
        assert exit_code == 2

    def test_all_paths_healthy(self, mock_context, multipath_healthy, multipathd_daemon_running):
        """Returns 0 when all multipath devices are healthy."""
        from scripts.baremetal import multipath_health

        ctx = mock_context(
            tools_available=["multipath", "multipathd"],
            command_outputs={
                ("multipathd", "show", "daemon"): multipathd_daemon_running,
                ("multipathd", "show", "topology"): multipath_healthy,
            }
        )
        output = Output()

        exit_code = multipath_health.run([], output, ctx)

        assert exit_code == 0
        assert "devices" in output.data
        assert len(output.data["devices"]) == 2
        assert all(d["failed_paths"] == 0 for d in output.data["devices"])

    def test_degraded_path(self, mock_context, multipath_degraded, multipathd_daemon_running):
        """Returns 1 when a path has failed."""
        from scripts.baremetal import multipath_health

        ctx = mock_context(
            tools_available=["multipath", "multipathd"],
            command_outputs={
                ("multipathd", "show", "daemon"): multipathd_daemon_running,
                ("multipathd", "show", "topology"): multipath_degraded,
            }
        )
        output = Output()

        exit_code = multipath_health.run([], output, ctx)

        assert exit_code == 1
        assert any(d["failed_paths"] > 0 for d in output.data["devices"])
        assert len(output.data["issues"]) > 0

    def test_no_active_paths(self, mock_context, multipath_no_paths, multipathd_daemon_running):
        """Returns 1 when device has no active paths."""
        from scripts.baremetal import multipath_health

        ctx = mock_context(
            tools_available=["multipath", "multipathd"],
            command_outputs={
                ("multipathd", "show", "daemon"): multipathd_daemon_running,
                ("multipathd", "show", "topology"): multipath_no_paths,
            }
        )
        output = Output()

        exit_code = multipath_health.run([], output, ctx)

        assert exit_code == 1
        assert any(d["active_paths"] == 0 for d in output.data["devices"])
        assert any(i["severity"] == "CRITICAL" for i in output.data["issues"])

    def test_four_path_healthy(self, mock_context, multipath_four_paths, multipathd_daemon_running):
        """Returns 0 for healthy four-path configuration."""
        from scripts.baremetal import multipath_health

        ctx = mock_context(
            tools_available=["multipath", "multipathd"],
            command_outputs={
                ("multipathd", "show", "daemon"): multipathd_daemon_running,
                ("multipathd", "show", "topology"): multipath_four_paths,
            }
        )
        output = Output()

        exit_code = multipath_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["devices"]) == 1
        assert output.data["devices"][0]["total_paths"] == 4
        assert output.data["devices"][0]["active_paths"] == 4

    def test_no_multipath_devices(self, mock_context, multipathd_daemon_running):
        """Returns 0 when no multipath devices configured."""
        from scripts.baremetal import multipath_health

        ctx = mock_context(
            tools_available=["multipath", "multipathd"],
            command_outputs={
                ("multipathd", "show", "daemon"): multipathd_daemon_running,
                ("multipathd", "show", "topology"): "",
                ("multipath", "-ll"): "",  # Fallback command
            }
        )
        output = Output()

        exit_code = multipath_health.run([], output, ctx)

        assert exit_code == 0
        assert "No multipath" in output.data.get("message", "")
