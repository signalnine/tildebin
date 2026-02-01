"""Tests for volume_attachment script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def volume_attachments_healthy(fixtures_dir):
    """Load healthy volume attachments fixture."""
    return (fixtures_dir / "k8s" / "volume_attachments_healthy.json").read_text()


@pytest.fixture
def volume_attachments_with_issues(fixtures_dir):
    """Load volume attachments with issues fixture."""
    return (fixtures_dir / "k8s" / "volume_attachments_with_issues.json").read_text()


@pytest.fixture
def nodes_healthy(fixtures_dir):
    """Load healthy nodes fixture."""
    return (fixtures_dir / "k8s" / "nodes_healthy.json").read_text()


@pytest.fixture
def nodes_with_issues(fixtures_dir):
    """Load nodes with issues fixture."""
    return (fixtures_dir / "k8s" / "nodes_with_issues.json").read_text()


@pytest.fixture
def pvs_healthy(fixtures_dir):
    """Load healthy PVs fixture."""
    return (fixtures_dir / "k8s" / "pvs_healthy.json").read_text()


class TestVolumeAttachment:
    """Tests for volume_attachment script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import volume_attachment

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = volume_attachment.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_healthy(self, mock_context, volume_attachments_healthy,
                         nodes_healthy, pvs_healthy):
        """Returns 0 when all VolumeAttachments are healthy."""
        from scripts.k8s import volume_attachment

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
                ("kubectl", "get", "nodes", "-o", "json"): nodes_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = volume_attachment.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total"] == 2
        assert output.data["summary"]["with_issues"] == 0

    def test_attachments_with_issues(self, mock_context, volume_attachments_with_issues,
                                      nodes_healthy, pvs_healthy):
        """Returns 1 when VolumeAttachments have issues."""
        from scripts.k8s import volume_attachment

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_with_issues,
                ("kubectl", "get", "nodes", "-o", "json"): nodes_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = volume_attachment.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["with_issues"] > 0

    def test_detects_attach_errors(self, mock_context, volume_attachments_with_issues,
                                    nodes_healthy, pvs_healthy):
        """Detects attachment errors."""
        from scripts.k8s import volume_attachment

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_with_issues,
                ("kubectl", "get", "nodes", "-o", "json"): nodes_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = volume_attachment.run([], output, ctx)

        # Should find attachment with attach error
        attachments_with_attach_errors = [
            a for a in output.data["attachments"]
            if any(i["type"] == "attach_error" for i in a["issues"])
        ]
        assert len(attachments_with_attach_errors) > 0

    def test_warn_only_filters_healthy(self, mock_context, volume_attachments_with_issues,
                                        nodes_healthy, pvs_healthy):
        """--warn-only only shows VolumeAttachments with issues."""
        from scripts.k8s import volume_attachment

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_with_issues,
                ("kubectl", "get", "nodes", "-o", "json"): nodes_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = volume_attachment.run(["--warn-only"], output, ctx)

        # All returned attachments should have issues
        for att in output.data["attachments"]:
            assert len(att["issues"]) > 0

    def test_empty_volume_attachments(self, mock_context, nodes_healthy, pvs_healthy):
        """Returns 0 when no VolumeAttachments exist."""
        from scripts.k8s import volume_attachment

        empty_vas = '{"items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumeattachments", "-o", "json"): empty_vas,
                ("kubectl", "get", "nodes", "-o", "json"): nodes_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        exit_code = volume_attachment.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total"] == 0

    def test_stale_hours_threshold(self, mock_context, volume_attachments_healthy,
                                    nodes_healthy, pvs_healthy):
        """--stale-hours configures stale threshold."""
        from scripts.k8s import volume_attachment

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumeattachments", "-o", "json"): volume_attachments_healthy,
                ("kubectl", "get", "nodes", "-o", "json"): nodes_healthy,
                ("kubectl", "get", "pv", "-o", "json"): pvs_healthy,
            }
        )
        output = Output()

        # Should complete without error
        exit_code = volume_attachment.run(["--stale-hours", "48"], output, ctx)

        assert exit_code in [0, 1]
