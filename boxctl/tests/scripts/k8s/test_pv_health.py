"""Tests for pv_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def pvs_healthy(fixtures_dir):
    """Load healthy PVs fixture."""
    return (fixtures_dir / "k8s" / "pvs_healthy.json").read_text()


@pytest.fixture
def pvs_with_issues(fixtures_dir):
    """Load PVs with issues fixture."""
    return (fixtures_dir / "k8s" / "pvs_with_issues.json").read_text()


@pytest.fixture
def pvs_empty(fixtures_dir):
    """Load empty PVs fixture."""
    return (fixtures_dir / "k8s" / "pvs_empty.json").read_text()


@pytest.fixture
def pvcs_healthy(fixtures_dir):
    """Load healthy PVCs fixture."""
    return (fixtures_dir / "k8s" / "pvcs_healthy.json").read_text()


class TestPvHealth:
    """Tests for pv_health script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import pv_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = pv_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_pvs_healthy(self, mock_context, pvs_healthy, pvcs_healthy):
        """Returns 0 when all PVs are healthy."""
        from scripts.k8s import pv_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
                ("kubectl", "get", "pvc", "-A", "-o", "json"): pvcs_healthy,
            }
        )
        output = Output()

        exit_code = pv_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["total"] == 2
        assert output.data["healthy"] == 2
        assert output.data["with_issues"] == 0

    def test_pvs_with_issues(self, mock_context, pvs_with_issues, pvcs_healthy):
        """Returns 1 when PVs have issues."""
        from scripts.k8s import pv_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pv", "-o", "json"): pvs_with_issues,
                ("kubectl", "get", "pvc", "-A", "-o", "json"): pvcs_healthy,
            }
        )
        output = Output()

        exit_code = pv_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["with_issues"] > 0
        # Check specific issues
        issues_found = [pv for pv in output.data["pvs"] if pv["issues"]]
        assert len(issues_found) > 0

    def test_warn_only_filters_healthy(self, mock_context, pvs_with_issues, pvcs_healthy):
        """--warn-only only shows PVs with issues."""
        from scripts.k8s import pv_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pv", "-o", "json"): pvs_with_issues,
                ("kubectl", "get", "pvc", "-A", "-o", "json"): pvcs_healthy,
            }
        )
        output = Output()

        exit_code = pv_health.run(["--warn-only"], output, ctx)

        assert exit_code == 1
        # All returned PVs should have issues
        for pv in output.data["pvs"]:
            assert len(pv["issues"]) > 0

    def test_empty_pvs(self, mock_context, pvs_empty, pvcs_healthy):
        """Returns 0 when no PVs exist."""
        from scripts.k8s import pv_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pv", "-o", "json"): pvs_empty,
                ("kubectl", "get", "pvc", "-A", "-o", "json"): pvcs_healthy,
            }
        )
        output = Output()

        exit_code = pv_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["total"] == 0
        assert output.data["healthy"] == 0

    def test_released_pv_with_retain_policy(self, mock_context, pvs_with_issues, pvcs_healthy):
        """Detects Released PVs with Retain policy."""
        from scripts.k8s import pv_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pv", "-o", "json"): pvs_with_issues,
                ("kubectl", "get", "pvc", "-A", "-o", "json"): pvcs_healthy,
            }
        )
        output = Output()

        exit_code = pv_health.run([], output, ctx)

        # Find the released PV
        released_pv = next((pv for pv in output.data["pvs"] if pv["phase"] == "Released"), None)
        assert released_pv is not None
        assert any("Released" in issue or "Retain" in issue for issue in released_pv["issues"])
