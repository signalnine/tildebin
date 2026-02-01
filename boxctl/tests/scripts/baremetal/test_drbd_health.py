"""Tests for drbd_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def drbd_status_healthy(fixtures_dir):
    """Load healthy DRBD status."""
    return (fixtures_dir / "storage" / "drbd_status_healthy.txt").read_text()


@pytest.fixture
def drbd_status_disconnected(fixtures_dir):
    """Load disconnected DRBD status."""
    return (fixtures_dir / "storage" / "drbd_status_disconnected.txt").read_text()


@pytest.fixture
def drbd_status_syncing(fixtures_dir):
    """Load syncing DRBD status."""
    return (fixtures_dir / "storage" / "drbd_status_syncing.txt").read_text()


@pytest.fixture
def drbd_status_split_brain(fixtures_dir):
    """Load split-brain DRBD status."""
    return (fixtures_dir / "storage" / "drbd_status_split_brain.txt").read_text()


@pytest.fixture
def drbd_status_degraded(fixtures_dir):
    """Load degraded DRBD status."""
    return (fixtures_dir / "storage" / "drbd_status_degraded.txt").read_text()


@pytest.fixture
def drbd_json_healthy(fixtures_dir):
    """Load healthy DRBD JSON status."""
    return (fixtures_dir / "storage" / "drbd_json_healthy.json").read_text()


@pytest.fixture
def drbd_json_syncing(fixtures_dir):
    """Load syncing DRBD JSON status."""
    return (fixtures_dir / "storage" / "drbd_json_syncing.json").read_text()


class TestDrbdHealth:
    """Tests for drbd_health script."""

    def test_missing_drbdadm_returns_error(self, mock_context):
        """Returns exit code 2 when drbdadm not available."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("drbdadm" in e.lower() for e in output.errors)

    def test_no_resources_returns_healthy(self, mock_context):
        """Returns 0 when no DRBD resources configured."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(
            tools_available=["drbdadm", "drbdsetup"],
            command_outputs={
                ("drbdsetup", "status", "--json"): "",
                ("drbdadm", "status"): "",
            }
        )
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        assert exit_code == 0
        assert "resources" in output.data

    def test_healthy_resources_returns_zero(self, mock_context, drbd_status_healthy):
        """Returns 0 when all DRBD resources are healthy."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(
            tools_available=["drbdadm", "drbdsetup"],
            command_outputs={
                ("drbdsetup", "status", "--json"): "",  # Not available
                ("drbdadm", "status"): drbd_status_healthy,
            }
        )
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["resources"]) == 2
        assert len([i for i in output.data["issues"] if i["severity"] in ("CRITICAL", "WARNING")]) == 0

    def test_disconnected_resource_returns_one(self, mock_context, drbd_status_disconnected):
        """Returns 1 when a DRBD resource is disconnected."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(
            tools_available=["drbdadm", "drbdsetup"],
            command_outputs={
                ("drbdsetup", "status", "--json"): "",
                ("drbdadm", "status"): drbd_status_disconnected,
            }
        )
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        assert exit_code == 1
        assert any("standalone" in i["message"].lower() for i in output.data["issues"])

    def test_split_brain_detected_as_critical(self, mock_context, drbd_status_split_brain):
        """Detects split-brain as critical issue."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(
            tools_available=["drbdadm", "drbdsetup"],
            command_outputs={
                ("drbdsetup", "status", "--json"): "",
                ("drbdadm", "status"): drbd_status_split_brain,
            }
        )
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        assert exit_code == 1
        assert any("split-brain" in i["message"].lower() and i["severity"] == "CRITICAL"
                   for i in output.data["issues"])

    def test_syncing_resource_shows_progress(self, mock_context, drbd_status_syncing):
        """Shows sync progress for syncing resources."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(
            tools_available=["drbdadm", "drbdsetup"],
            command_outputs={
                ("drbdsetup", "status", "--json"): "",
                ("drbdadm", "status"): drbd_status_syncing,
            }
        )
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        # Syncing at 45% should trigger warning (below default 90%)
        assert exit_code == 1
        assert any("sync" in i["message"].lower() for i in output.data["issues"])

    def test_json_status_parsing(self, mock_context, drbd_json_healthy):
        """Correctly parses DRBD 9+ JSON status."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(
            tools_available=["drbdadm", "drbdsetup"],
            command_outputs={
                ("drbdsetup", "status", "--json"): drbd_json_healthy,
            }
        )
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["resources"]) == 1
        assert output.data["resources"][0]["name"] == "r0"

    def test_degraded_disk_returns_one(self, mock_context, drbd_status_degraded):
        """Returns 1 when disk state is Inconsistent."""
        from scripts.baremetal import drbd_health

        ctx = mock_context(
            tools_available=["drbdadm", "drbdsetup"],
            command_outputs={
                ("drbdsetup", "status", "--json"): "",
                ("drbdadm", "status"): drbd_status_degraded,
            }
        )
        output = Output()

        exit_code = drbd_health.run([], output, ctx)

        assert exit_code == 1
        assert any("inconsistent" in i["message"].lower() for i in output.data["issues"])
