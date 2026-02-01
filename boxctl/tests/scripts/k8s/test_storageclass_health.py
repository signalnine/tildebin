"""Tests for storageclass_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def storageclasses_healthy(fixtures_dir):
    """Load healthy storage classes fixture."""
    return (fixtures_dir / "k8s" / "storageclasses_healthy.json").read_text()


@pytest.fixture
def storageclasses_no_default(fixtures_dir):
    """Load storage classes without default fixture."""
    return (fixtures_dir / "k8s" / "storageclasses_no_default.json").read_text()


@pytest.fixture
def storageclasses_multiple_default(fixtures_dir):
    """Load storage classes with multiple defaults fixture."""
    return (fixtures_dir / "k8s" / "storageclasses_multiple_default.json").read_text()


@pytest.fixture
def csi_pods_healthy(fixtures_dir):
    """Load healthy CSI pods fixture."""
    return (fixtures_dir / "k8s" / "csi_pods_healthy.json").read_text()


@pytest.fixture
def csi_pods_with_issues(fixtures_dir):
    """Load CSI pods with issues fixture."""
    return (fixtures_dir / "k8s" / "csi_pods_with_issues.json").read_text()


@pytest.fixture
def pvcs_healthy(fixtures_dir):
    """Load healthy PVCs fixture."""
    return (fixtures_dir / "k8s" / "pvcs_healthy.json").read_text()


@pytest.fixture
def volume_attachments_healthy(fixtures_dir):
    """Load healthy volume attachments fixture."""
    return (fixtures_dir / "k8s" / "volume_attachments_healthy.json").read_text()


class TestStorageclassHealth:
    """Tests for storageclass_health script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import storageclass_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = storageclass_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_healthy(self, mock_context, storageclasses_healthy, csi_pods_healthy,
                         pvcs_healthy, volume_attachments_healthy):
        """Returns 0 when everything is healthy."""
        from scripts.k8s import storageclass_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_healthy,
                ("kubectl", "get", "pods", "-n", "kube-system", "-o", "json"): csi_pods_healthy,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_healthy,
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
            }
        )
        output = Output()

        exit_code = storageclass_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "healthy"
        assert output.data["issue_count"] == 0

    def test_no_default_storageclass(self, mock_context, storageclasses_no_default,
                                      csi_pods_healthy, pvcs_healthy, volume_attachments_healthy):
        """Returns 1 when no default StorageClass configured."""
        from scripts.k8s import storageclass_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_no_default,
                ("kubectl", "get", "pods", "-n", "kube-system", "-o", "json"): csi_pods_healthy,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_healthy,
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
            }
        )
        output = Output()

        exit_code = storageclass_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "unhealthy"
        assert any("default" in issue.lower() for issue in output.data["issues"])

    def test_multiple_default_storageclasses(self, mock_context, storageclasses_multiple_default,
                                              csi_pods_healthy, pvcs_healthy, volume_attachments_healthy):
        """Returns 1 when multiple default StorageClasses configured."""
        from scripts.k8s import storageclass_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_multiple_default,
                ("kubectl", "get", "pods", "-n", "kube-system", "-o", "json"): csi_pods_healthy,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_healthy,
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
            }
        )
        output = Output()

        exit_code = storageclass_health.run([], output, ctx)

        assert exit_code == 1
        assert any("multiple" in issue.lower() for issue in output.data["issues"])

    def test_csi_pods_with_issues(self, mock_context, storageclasses_healthy,
                                   csi_pods_with_issues, pvcs_healthy, volume_attachments_healthy):
        """Returns 1 when CSI pods have issues."""
        from scripts.k8s import storageclass_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_healthy,
                ("kubectl", "get", "pods", "-n", "kube-system", "-o", "json"): csi_pods_with_issues,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_healthy,
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
            }
        )
        output = Output()

        exit_code = storageclass_health.run([], output, ctx)

        assert exit_code == 1
        assert any("csi" in issue.lower() for issue in output.data["issues"])

    def test_empty_storageclasses(self, mock_context, csi_pods_healthy,
                                   pvcs_healthy, volume_attachments_healthy):
        """Returns 1 when no StorageClasses found."""
        from scripts.k8s import storageclass_health

        empty_sc = '{"items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "storageclasses", "-o", "json"): empty_sc,
                ("kubectl", "get", "pods", "-n", "kube-system", "-o", "json"): csi_pods_healthy,
                ("kubectl", "get", "pvc", "-o", "json", "--all-namespaces"): pvcs_healthy,
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
            }
        )
        output = Output()

        exit_code = storageclass_health.run([], output, ctx)

        assert exit_code == 1
        assert any("no storageclasses" in issue.lower() for issue in output.data["issues"])

    def test_namespace_filter(self, mock_context, storageclasses_healthy,
                               csi_pods_healthy, pvcs_healthy, volume_attachments_healthy):
        """--namespace filters PVC checks to specific namespace."""
        from scripts.k8s import storageclass_health

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "storageclasses", "-o", "json"): storageclasses_healthy,
                ("kubectl", "get", "pods", "-n", "kube-system", "-o", "json"): csi_pods_healthy,
                ("kubectl", "get", "pvc", "-o", "json", "-n", "production"): pvcs_healthy,
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
            }
        )
        output = Output()

        exit_code = storageclass_health.run(["--namespace", "production"], output, ctx)

        # Should complete without error
        assert exit_code in [0, 1]
