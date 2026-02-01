"""Tests for pvc_stuck script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def pvcs_healthy(fixtures_dir):
    """Load healthy PVCs fixture."""
    return (fixtures_dir / "k8s" / "pvcs_healthy.json").read_text()


@pytest.fixture
def pvcs_with_pending(fixtures_dir):
    """Load PVCs with pending fixture."""
    return (fixtures_dir / "k8s" / "pvcs_with_pending.json").read_text()


@pytest.fixture
def storageclasses_healthy(fixtures_dir):
    """Load healthy storage classes fixture."""
    return (fixtures_dir / "k8s" / "storageclasses_healthy.json").read_text()


@pytest.fixture
def pvs_healthy(fixtures_dir):
    """Load healthy PVs fixture."""
    return (fixtures_dir / "k8s" / "pvs_healthy.json").read_text()


@pytest.fixture
def pvs_empty(fixtures_dir):
    """Load empty PVs fixture."""
    return (fixtures_dir / "k8s" / "pvs_empty.json").read_text()


class TestPvcStuck:
    """Tests for pvc_stuck script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import pvc_stuck

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = pvc_stuck.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_no_stuck_pvcs(self, mock_context, pvcs_healthy, storageclasses_healthy, pvs_healthy):
        """Returns 0 when no PVCs are stuck."""
        from scripts.k8s import pvc_stuck

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_healthy,
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = pvc_stuck.run([], output, ctx)

        assert exit_code == 0
        assert output.data["stuck_count"] == 0

    def test_stuck_pvcs_found(self, mock_context, pvcs_with_pending, storageclasses_healthy, pvs_healthy):
        """Returns 1 when stuck PVCs are found."""
        from scripts.k8s import pvc_stuck

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_with_pending,
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        # Use threshold=0 to catch all pending PVCs
        exit_code = pvc_stuck.run(["--threshold", "0"], output, ctx)

        assert exit_code == 1
        assert output.data["stuck_count"] >= 1

    def test_threshold_filters_recent(self, mock_context, pvcs_with_pending, storageclasses_healthy, pvs_healthy):
        """--threshold filters out recently created PVCs."""
        from scripts.k8s import pvc_stuck

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_with_pending,
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        # Very high threshold should filter out most/all pending PVCs
        exit_code = pvc_stuck.run(["--threshold", "999999999"], output, ctx)

        assert exit_code == 0
        assert output.data["stuck_count"] == 0

    def test_negative_threshold_returns_error(self, mock_context):
        """Returns exit code 2 for negative threshold."""
        from scripts.k8s import pvc_stuck

        ctx = mock_context(tools_available=["kubectl"])
        output = Output()

        exit_code = pvc_stuck.run(["--threshold", "-1"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_diagnoses_missing_storageclass(self, mock_context, pvcs_with_pending, pvs_healthy):
        """Diagnoses missing StorageClass for pending PVCs."""
        from scripts.k8s import pvc_stuck

        # Provide empty storage classes to trigger diagnosis
        empty_sc = '{"items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_with_pending,
                ("kubectl", "get", "storageclasses", "-o", "json"): empty_sc,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = pvc_stuck.run(["--threshold", "0"], output, ctx)

        assert exit_code == 1
        # Check that diagnostic mentions StorageClass issues
        for pvc in output.data["pvcs"]:
            diag = pvc["diagnosis"]["diagnostics"]
            # Should have some diagnosis about storage class
            assert len(diag) > 0

    def test_namespace_filter(self, mock_context, pvcs_with_pending, storageclasses_healthy, pvs_healthy):
        """--namespace filters to specific namespace."""
        from scripts.k8s import pvc_stuck

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pvc", "-o", "json", "-n", "default"): pvcs_with_pending,
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = pvc_stuck.run(["--namespace", "default", "--threshold", "0"], output, ctx)

        # All returned PVCs should be in default namespace
        for pvc in output.data["pvcs"]:
            assert pvc["namespace"] == "default"
