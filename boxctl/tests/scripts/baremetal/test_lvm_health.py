"""Tests for lvm_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def lvs_healthy(fixtures_dir):
    """Load healthy LVS output."""
    return (fixtures_dir / "storage" / "lvs_healthy.txt").read_text()


@pytest.fixture
def lvs_thin_pool_warning(fixtures_dir):
    """Load thin pool warning LVS output."""
    return (fixtures_dir / "storage" / "lvs_thin_pool_warning.txt").read_text()


@pytest.fixture
def lvs_thin_pool_critical(fixtures_dir):
    """Load thin pool critical LVS output."""
    return (fixtures_dir / "storage" / "lvs_thin_pool_critical.txt").read_text()


@pytest.fixture
def lvs_snapshot_full(fixtures_dir):
    """Load snapshot full LVS output."""
    return (fixtures_dir / "storage" / "lvs_snapshot_full.txt").read_text()


@pytest.fixture
def vgs_healthy(fixtures_dir):
    """Load healthy VGS output."""
    return (fixtures_dir / "storage" / "vgs_healthy.txt").read_text()


@pytest.fixture
def vgs_near_full(fixtures_dir):
    """Load near-full VGS output."""
    return (fixtures_dir / "storage" / "vgs_near_full.txt").read_text()


@pytest.fixture
def pvs_healthy(fixtures_dir):
    """Load healthy PVS output."""
    return (fixtures_dir / "storage" / "pvs_healthy.txt").read_text()


@pytest.fixture
def pvs_missing(fixtures_dir):
    """Load PVS output with missing PV."""
    return (fixtures_dir / "storage" / "pvs_missing.txt").read_text()


@pytest.fixture
def pvs_orphan(fixtures_dir):
    """Load PVS output with orphan PV."""
    return (fixtures_dir / "storage" / "pvs_orphan.txt").read_text()


class TestLvmHealth:
    """Tests for lvm_health script."""

    def test_missing_lvs_returns_error(self, mock_context):
        """Returns exit code 2 when lvs not available."""
        from scripts.baremetal import lvm_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = lvm_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("lvs" in e.lower() for e in output.errors)

    def test_all_lvm_healthy(self, mock_context, lvs_healthy, vgs_healthy, pvs_healthy):
        """Returns 0 when all LVM components are healthy."""
        from scripts.baremetal import lvm_health

        ctx = mock_context(
            tools_available=["lvs", "vgs", "pvs"],
            command_outputs={
                ("lvs", "--noheadings", "--separator", "|", "-o",
                 "lv_name,vg_name,lv_size,data_percent,metadata_percent,lv_attr,origin,snap_percent,pool_lv,lv_time",
                 "--units", "b"): lvs_healthy,
                ("vgs", "--noheadings", "--separator", "|", "-o",
                 "vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr",
                 "--units", "b"): vgs_healthy,
                ("pvs", "--noheadings", "--separator", "|", "-o",
                 "pv_name,vg_name,pv_size,pv_free,pv_attr",
                 "--units", "b"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = lvm_health.run([], output, ctx)

        assert exit_code == 0
        assert "issues" in output.data
        assert len(output.data["issues"]) == 0

    def test_thin_pool_warning(self, mock_context, lvs_thin_pool_warning, vgs_healthy, pvs_healthy):
        """Returns 1 when thin pool exceeds warning threshold."""
        from scripts.baremetal import lvm_health

        ctx = mock_context(
            tools_available=["lvs", "vgs", "pvs"],
            command_outputs={
                ("lvs", "--noheadings", "--separator", "|", "-o",
                 "lv_name,vg_name,lv_size,data_percent,metadata_percent,lv_attr,origin,snap_percent,pool_lv,lv_time",
                 "--units", "b"): lvs_thin_pool_warning,
                ("vgs", "--noheadings", "--separator", "|", "-o",
                 "vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr",
                 "--units", "b"): vgs_healthy,
                ("pvs", "--noheadings", "--separator", "|", "-o",
                 "pv_name,vg_name,pv_size,pv_free,pv_attr",
                 "--units", "b"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = lvm_health.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["issues"]) > 0
        assert any("thin pool" in i["message"].lower() for i in output.data["issues"])

    def test_thin_pool_critical(self, mock_context, lvs_thin_pool_critical, vgs_healthy, pvs_healthy):
        """Returns 1 with critical severity for thin pool over critical threshold."""
        from scripts.baremetal import lvm_health

        ctx = mock_context(
            tools_available=["lvs", "vgs", "pvs"],
            command_outputs={
                ("lvs", "--noheadings", "--separator", "|", "-o",
                 "lv_name,vg_name,lv_size,data_percent,metadata_percent,lv_attr,origin,snap_percent,pool_lv,lv_time",
                 "--units", "b"): lvs_thin_pool_critical,
                ("vgs", "--noheadings", "--separator", "|", "-o",
                 "vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr",
                 "--units", "b"): vgs_healthy,
                ("pvs", "--noheadings", "--separator", "|", "-o",
                 "pv_name,vg_name,pv_size,pv_free,pv_attr",
                 "--units", "b"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = lvm_health.run([], output, ctx)

        assert exit_code == 1
        assert any(i["severity"] == "CRITICAL" for i in output.data["issues"])

    def test_snapshot_full(self, mock_context, lvs_snapshot_full, vgs_healthy, pvs_healthy):
        """Returns 1 when snapshot is full."""
        from scripts.baremetal import lvm_health

        ctx = mock_context(
            tools_available=["lvs", "vgs", "pvs"],
            command_outputs={
                ("lvs", "--noheadings", "--separator", "|", "-o",
                 "lv_name,vg_name,lv_size,data_percent,metadata_percent,lv_attr,origin,snap_percent,pool_lv,lv_time",
                 "--units", "b"): lvs_snapshot_full,
                ("vgs", "--noheadings", "--separator", "|", "-o",
                 "vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr",
                 "--units", "b"): vgs_healthy,
                ("pvs", "--noheadings", "--separator", "|", "-o",
                 "pv_name,vg_name,pv_size,pv_free,pv_attr",
                 "--units", "b"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = lvm_health.run([], output, ctx)

        assert exit_code == 1
        assert any("snapshot" in i["message"].lower() and "full" in i["message"].lower()
                   for i in output.data["issues"])

    def test_vg_near_full(self, mock_context, lvs_healthy, vgs_near_full, pvs_healthy):
        """Returns 1 when volume group is near capacity."""
        from scripts.baremetal import lvm_health

        ctx = mock_context(
            tools_available=["lvs", "vgs", "pvs"],
            command_outputs={
                ("lvs", "--noheadings", "--separator", "|", "-o",
                 "lv_name,vg_name,lv_size,data_percent,metadata_percent,lv_attr,origin,snap_percent,pool_lv,lv_time",
                 "--units", "b"): lvs_healthy,
                ("vgs", "--noheadings", "--separator", "|", "-o",
                 "vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr",
                 "--units", "b"): vgs_near_full,
                ("pvs", "--noheadings", "--separator", "|", "-o",
                 "pv_name,vg_name,pv_size,pv_free,pv_attr",
                 "--units", "b"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = lvm_health.run([], output, ctx)

        assert exit_code == 1
        assert any("volume group" in i["message"].lower() for i in output.data["issues"])

    def test_pv_missing(self, mock_context, lvs_healthy, vgs_healthy, pvs_missing):
        """Returns 1 when a physical volume is missing."""
        from scripts.baremetal import lvm_health

        ctx = mock_context(
            tools_available=["lvs", "vgs", "pvs"],
            command_outputs={
                ("lvs", "--noheadings", "--separator", "|", "-o",
                 "lv_name,vg_name,lv_size,data_percent,metadata_percent,lv_attr,origin,snap_percent,pool_lv,lv_time",
                 "--units", "b"): lvs_healthy,
                ("vgs", "--noheadings", "--separator", "|", "-o",
                 "vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr",
                 "--units", "b"): vgs_healthy,
                ("pvs", "--noheadings", "--separator", "|", "-o",
                 "pv_name,vg_name,pv_size,pv_free,pv_attr",
                 "--units", "b"): pvs_missing,
            }
        )
        output = Output()

        exit_code = lvm_health.run([], output, ctx)

        assert exit_code == 1
        assert any(i["severity"] == "CRITICAL" and "missing" in i["message"].lower()
                   for i in output.data["issues"])
