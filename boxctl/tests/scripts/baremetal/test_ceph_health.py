"""Tests for ceph_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def ceph_status_healthy(fixtures_dir):
    """Load healthy cluster status."""
    return (fixtures_dir / "storage" / "ceph_status_healthy.json").read_text()


@pytest.fixture
def ceph_status_warn(fixtures_dir):
    """Load warning cluster status."""
    return (fixtures_dir / "storage" / "ceph_status_warn.json").read_text()


@pytest.fixture
def ceph_status_err(fixtures_dir):
    """Load error cluster status."""
    return (fixtures_dir / "storage" / "ceph_status_err.json").read_text()


@pytest.fixture
def ceph_osd_tree_healthy(fixtures_dir):
    """Load healthy OSD tree."""
    return (fixtures_dir / "storage" / "ceph_osd_tree_healthy.json").read_text()


@pytest.fixture
def ceph_osd_tree_down(fixtures_dir):
    """Load OSD tree with down OSD."""
    return (fixtures_dir / "storage" / "ceph_osd_tree_down.json").read_text()


@pytest.fixture
def ceph_osd_df_healthy(fixtures_dir):
    """Load healthy OSD df output."""
    return (fixtures_dir / "storage" / "ceph_osd_df_healthy.json").read_text()


@pytest.fixture
def ceph_df_detail_healthy(fixtures_dir):
    """Load healthy pool stats."""
    return (fixtures_dir / "storage" / "ceph_df_detail_healthy.json").read_text()


class TestCephHealth:
    """Tests for ceph_health script."""

    def test_missing_ceph_returns_error(self, mock_context):
        """Returns exit code 2 when ceph not available."""
        from scripts.baremetal import ceph_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = ceph_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("ceph" in e.lower() for e in output.errors)

    def test_healthy_cluster(
        self,
        mock_context,
        ceph_status_healthy,
        ceph_osd_tree_healthy,
        ceph_osd_df_healthy,
        ceph_df_detail_healthy,
    ):
        """Returns 0 when cluster is healthy."""
        from scripts.baremetal import ceph_health

        ctx = mock_context(
            tools_available=["ceph"],
            command_outputs={
                ("ceph", "status", "--format", "json"): ceph_status_healthy,
                ("ceph", "osd", "tree", "--format", "json"): ceph_osd_tree_healthy,
                ("ceph", "osd", "df", "--format", "json"): ceph_osd_df_healthy,
                ("ceph", "df", "detail", "--format", "json"): ceph_df_detail_healthy,
            }
        )
        output = Output()

        exit_code = ceph_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["health"]["status"] == "HEALTH_OK"
        assert output.data["warnings"] == []

    def test_cluster_warning(
        self,
        mock_context,
        ceph_status_warn,
        ceph_osd_tree_healthy,
        ceph_osd_df_healthy,
        ceph_df_detail_healthy,
    ):
        """Returns 1 when cluster has warnings."""
        from scripts.baremetal import ceph_health

        ctx = mock_context(
            tools_available=["ceph"],
            command_outputs={
                ("ceph", "status", "--format", "json"): ceph_status_warn,
                ("ceph", "osd", "tree", "--format", "json"): ceph_osd_tree_healthy,
                ("ceph", "osd", "df", "--format", "json"): ceph_osd_df_healthy,
                ("ceph", "df", "detail", "--format", "json"): ceph_df_detail_healthy,
            }
        )
        output = Output()

        exit_code = ceph_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["health"]["status"] == "HEALTH_WARN"

    def test_cluster_error(
        self,
        mock_context,
        ceph_status_err,
        ceph_osd_tree_down,
        ceph_osd_df_healthy,
        ceph_df_detail_healthy,
    ):
        """Returns 1 when cluster has errors."""
        from scripts.baremetal import ceph_health

        ctx = mock_context(
            tools_available=["ceph"],
            command_outputs={
                ("ceph", "status", "--format", "json"): ceph_status_err,
                ("ceph", "osd", "tree", "--format", "json"): ceph_osd_tree_down,
                ("ceph", "osd", "df", "--format", "json"): ceph_osd_df_healthy,
                ("ceph", "df", "detail", "--format", "json"): ceph_df_detail_healthy,
            }
        )
        output = Output()

        exit_code = ceph_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["health"]["status"] == "HEALTH_ERR"

    def test_osd_down_detected(
        self,
        mock_context,
        ceph_status_healthy,
        ceph_osd_tree_down,
        ceph_osd_df_healthy,
        ceph_df_detail_healthy,
    ):
        """Detects when an OSD is down."""
        from scripts.baremetal import ceph_health

        ctx = mock_context(
            tools_available=["ceph"],
            command_outputs={
                ("ceph", "status", "--format", "json"): ceph_status_healthy,
                ("ceph", "osd", "tree", "--format", "json"): ceph_osd_tree_down,
                ("ceph", "osd", "df", "--format", "json"): ceph_osd_df_healthy,
                ("ceph", "df", "detail", "--format", "json"): ceph_df_detail_healthy,
            }
        )
        output = Output()

        exit_code = ceph_health.run([], output, ctx)

        # Check that OSD down is detected in warnings
        assert output.data["osds"]["down"] == 1
        assert any("down" in w["message"].lower() for w in output.data["warnings"])

    def test_verbose_output(
        self,
        mock_context,
        ceph_status_healthy,
        ceph_osd_tree_healthy,
        ceph_osd_df_healthy,
        ceph_df_detail_healthy,
    ):
        """--verbose includes detailed OSD and pool info."""
        from scripts.baremetal import ceph_health

        ctx = mock_context(
            tools_available=["ceph"],
            command_outputs={
                ("ceph", "status", "--format", "json"): ceph_status_healthy,
                ("ceph", "osd", "tree", "--format", "json"): ceph_osd_tree_healthy,
                ("ceph", "osd", "df", "--format", "json"): ceph_osd_df_healthy,
                ("ceph", "df", "detail", "--format", "json"): ceph_df_detail_healthy,
            }
        )
        output = Output()

        exit_code = ceph_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "details" in output.data["osds"]
        assert "pools" in output.data

    def test_degraded_pgs_detected(
        self,
        mock_context,
        ceph_status_warn,
        ceph_osd_tree_healthy,
        ceph_osd_df_healthy,
        ceph_df_detail_healthy,
    ):
        """Detects degraded placement groups."""
        from scripts.baremetal import ceph_health

        ctx = mock_context(
            tools_available=["ceph"],
            command_outputs={
                ("ceph", "status", "--format", "json"): ceph_status_warn,
                ("ceph", "osd", "tree", "--format", "json"): ceph_osd_tree_healthy,
                ("ceph", "osd", "df", "--format", "json"): ceph_osd_df_healthy,
                ("ceph", "df", "detail", "--format", "json"): ceph_df_detail_healthy,
            }
        )
        output = Output()

        exit_code = ceph_health.run([], output, ctx)

        assert output.data["pgs"]["degraded"] > 0
