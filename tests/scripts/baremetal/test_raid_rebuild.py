"""Tests for raid_rebuild script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def mdstat_healthy(fixtures_dir):
    """Load healthy mdstat output."""
    return (fixtures_dir / "storage" / "mdstat_healthy.txt").read_text()


@pytest.fixture
def mdstat_rebuilding(fixtures_dir):
    """Load rebuilding mdstat output."""
    return (fixtures_dir / "storage" / "mdstat_rebuilding.txt").read_text()


@pytest.fixture
def mdstat_degraded(fixtures_dir):
    """Load degraded mdstat output."""
    return (fixtures_dir / "storage" / "mdstat_degraded.txt").read_text()


@pytest.fixture
def mdstat_check(fixtures_dir):
    """Load check/resync mdstat output."""
    return (fixtures_dir / "storage" / "mdstat_check.txt").read_text()


@pytest.fixture
def mdstat_raid5(fixtures_dir):
    """Load RAID5 mdstat output."""
    return (fixtures_dir / "storage" / "mdstat_raid5.txt").read_text()


class TestRaidRebuild:
    """Tests for raid_rebuild script."""

    def test_missing_mdstat_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/mdstat not found."""
        from scripts.baremetal import raid_rebuild

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = raid_rebuild.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("mdstat" in e.lower() for e in output.errors)

    def test_all_arrays_healthy(self, mock_context, mdstat_healthy):
        """Returns 0 when all RAID arrays are healthy."""
        from scripts.baremetal import raid_rebuild

        ctx = mock_context(
            file_contents={
                "/proc/mdstat": mdstat_healthy,
            }
        )
        output = Output()

        exit_code = raid_rebuild.run([], output, ctx)

        assert exit_code == 0
        assert "arrays" in output.data
        assert len(output.data["arrays"]) == 2
        assert all(not a["rebuild_in_progress"] for a in output.data["arrays"])
        assert all(not a.get("degraded") for a in output.data["arrays"])

    def test_rebuild_in_progress(self, mock_context, mdstat_rebuilding):
        """Returns 1 when RAID array is rebuilding."""
        from scripts.baremetal import raid_rebuild

        ctx = mock_context(
            file_contents={
                "/proc/mdstat": mdstat_rebuilding,
            }
        )
        output = Output()

        exit_code = raid_rebuild.run([], output, ctx)

        assert exit_code == 1
        assert any(a["rebuild_in_progress"] for a in output.data["arrays"])
        # Find the rebuilding array
        rebuilding = [a for a in output.data["arrays"] if a["rebuild_in_progress"]][0]
        assert rebuilding["operation"] == "recovery"
        assert rebuilding["progress_percent"] == 12.5

    def test_degraded_array(self, mock_context, mdstat_degraded):
        """Returns 1 when RAID array is degraded."""
        from scripts.baremetal import raid_rebuild

        ctx = mock_context(
            file_contents={
                "/proc/mdstat": mdstat_degraded,
            }
        )
        output = Output()

        exit_code = raid_rebuild.run([], output, ctx)

        assert exit_code == 1
        assert any(a.get("degraded") for a in output.data["arrays"])

    def test_check_in_progress(self, mock_context, mdstat_check):
        """Returns 1 when RAID array check is in progress."""
        from scripts.baremetal import raid_rebuild

        ctx = mock_context(
            file_contents={
                "/proc/mdstat": mdstat_check,
            }
        )
        output = Output()

        exit_code = raid_rebuild.run([], output, ctx)

        assert exit_code == 1
        assert any(a["rebuild_in_progress"] for a in output.data["arrays"])
        # Find the checking array
        checking = [a for a in output.data["arrays"] if a["rebuild_in_progress"]][0]
        assert checking["operation"] == "check"
        assert checking["progress_percent"] == 42.3

    def test_raid5_healthy(self, mock_context, mdstat_raid5):
        """Returns 0 for healthy RAID5 array."""
        from scripts.baremetal import raid_rebuild

        ctx = mock_context(
            file_contents={
                "/proc/mdstat": mdstat_raid5,
            }
        )
        output = Output()

        exit_code = raid_rebuild.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["arrays"]) == 1
        assert output.data["arrays"][0]["level"] == "raid5"
        assert not output.data["arrays"][0]["rebuild_in_progress"]

    def test_specific_array_filter(self, mock_context, mdstat_healthy):
        """--array filters to specific array."""
        from scripts.baremetal import raid_rebuild

        ctx = mock_context(
            file_contents={
                "/proc/mdstat": mdstat_healthy,
            }
        )
        output = Output()

        exit_code = raid_rebuild.run(["--array", "md0"], output, ctx)

        assert exit_code == 0
        assert len(output.data["arrays"]) == 1
        assert output.data["arrays"][0]["name"] == "md0"
