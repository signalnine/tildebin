"""Tests for volume_snapshot script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def volume_snapshots_healthy(fixtures_dir):
    """Load healthy volume snapshots fixture."""
    return (fixtures_dir / "k8s" / "volume_snapshots_healthy.json").read_text()


@pytest.fixture
def volume_snapshots_with_issues(fixtures_dir):
    """Load volume snapshots with issues fixture."""
    return (fixtures_dir / "k8s" / "volume_snapshots_with_issues.json").read_text()


@pytest.fixture
def volume_snapshot_contents_healthy(fixtures_dir):
    """Load healthy volume snapshot contents fixture."""
    return (fixtures_dir / "k8s" / "volume_snapshot_contents_healthy.json").read_text()


@pytest.fixture
def volume_snapshot_contents_with_orphan(fixtures_dir):
    """Load volume snapshot contents with orphan fixture."""
    return (fixtures_dir / "k8s" / "volume_snapshot_contents_with_orphan.json").read_text()


@pytest.fixture
def volume_snapshot_classes_healthy(fixtures_dir):
    """Load healthy volume snapshot classes fixture."""
    return (fixtures_dir / "k8s" / "volume_snapshot_classes_healthy.json").read_text()


class TestVolumeSnapshot:
    """Tests for volume_snapshot script."""

    def test_missing_kubectl_returns_error(self, mock_context):
        """Returns exit code 2 when kubectl not available."""
        from scripts.k8s import volume_snapshot

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = volume_snapshot.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("kubectl" in e.lower() for e in output.errors)

    def test_all_healthy(self, mock_context, volume_snapshots_healthy,
                         volume_snapshot_contents_healthy, volume_snapshot_classes_healthy):
        """Returns 0 when all snapshots are healthy."""
        from scripts.k8s import volume_snapshot

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumesnapshots", "-o", "json", "--all-namespaces"): volume_snapshots_healthy,
                ("kubectl", "get", "volumesnapshotcontents", "-o", "json"): volume_snapshot_contents_healthy,
                ("kubectl", "get", "volumesnapshotclasses", "-o", "json"): volume_snapshot_classes_healthy,
            }
        )
        output = Output()

        exit_code = volume_snapshot.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["healthySnapshots"] == 2
        assert output.data["summary"]["unhealthySnapshots"] == 0

    def test_snapshots_with_issues(self, mock_context, volume_snapshots_with_issues,
                                    volume_snapshot_contents_healthy, volume_snapshot_classes_healthy):
        """Returns 1 when snapshots have issues."""
        from scripts.k8s import volume_snapshot

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumesnapshots", "-o", "json", "--all-namespaces"): volume_snapshots_with_issues,
                ("kubectl", "get", "volumesnapshotcontents", "-o", "json"): volume_snapshot_contents_healthy,
                ("kubectl", "get", "volumesnapshotclasses", "-o", "json"): volume_snapshot_classes_healthy,
            }
        )
        output = Output()

        exit_code = volume_snapshot.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["unhealthySnapshots"] > 0

    def test_detects_orphaned_contents(self, mock_context, volume_snapshots_healthy,
                                        volume_snapshot_contents_with_orphan, volume_snapshot_classes_healthy):
        """Detects orphaned VolumeSnapshotContents."""
        from scripts.k8s import volume_snapshot

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumesnapshots", "-o", "json", "--all-namespaces"): volume_snapshots_healthy,
                ("kubectl", "get", "volumesnapshotcontents", "-o", "json"): volume_snapshot_contents_with_orphan,
                ("kubectl", "get", "volumesnapshotclasses", "-o", "json"): volume_snapshot_classes_healthy,
            }
        )
        output = Output()

        exit_code = volume_snapshot.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["orphanedContents"] > 0

    def test_warn_only_filters_healthy(self, mock_context, volume_snapshots_with_issues,
                                        volume_snapshot_contents_healthy, volume_snapshot_classes_healthy):
        """--warn-only only shows snapshots with issues."""
        from scripts.k8s import volume_snapshot

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumesnapshots", "-o", "json", "--all-namespaces"): volume_snapshots_with_issues,
                ("kubectl", "get", "volumesnapshotcontents", "-o", "json"): volume_snapshot_contents_healthy,
                ("kubectl", "get", "volumesnapshotclasses", "-o", "json"): volume_snapshot_classes_healthy,
            }
        )
        output = Output()

        exit_code = volume_snapshot.run(["--warn-only"], output, ctx)

        # All returned snapshots should have issues or warnings
        for snap in output.data["volumeSnapshots"]:
            assert len(snap["issues"]) > 0 or len(snap["warnings"]) > 0

    def test_retention_days_warning(self, mock_context, volume_snapshots_with_issues,
                                     volume_snapshot_contents_healthy, volume_snapshot_classes_healthy):
        """--retention-days warns about old snapshots."""
        from scripts.k8s import volume_snapshot

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumesnapshots", "-o", "json", "--all-namespaces"): volume_snapshots_with_issues,
                ("kubectl", "get", "volumesnapshotcontents", "-o", "json"): volume_snapshot_contents_healthy,
                ("kubectl", "get", "volumesnapshotclasses", "-o", "json"): volume_snapshot_classes_healthy,
            }
        )
        output = Output()

        # Very short retention should trigger warnings
        exit_code = volume_snapshot.run(["--retention-days", "1"], output, ctx)

        # Check if any warning mentions retention
        has_retention_warning = False
        for snap in output.data["volumeSnapshots"]:
            if any("retention" in w.lower() for w in snap["warnings"]):
                has_retention_warning = True
                break
        # Old snapshot in fixture should trigger warning
        assert has_retention_warning

    def test_empty_snapshots(self, mock_context, volume_snapshot_classes_healthy):
        """Returns 0 when no snapshots exist but classes present."""
        from scripts.k8s import volume_snapshot

        empty_snapshots = '{"items": []}'
        empty_contents = '{"items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumesnapshots", "-o", "json", "--all-namespaces"): empty_snapshots,
                ("kubectl", "get", "volumesnapshotcontents", "-o", "json"): empty_contents,
                ("kubectl", "get", "volumesnapshotclasses", "-o", "json"): volume_snapshot_classes_healthy,
            }
        )
        output = Output()

        exit_code = volume_snapshot.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["totalSnapshots"] == 0

    def test_no_snapshot_classes_returns_issue(self, mock_context, volume_snapshots_healthy,
                                                volume_snapshot_contents_healthy):
        """Returns 1 when no VolumeSnapshotClasses found."""
        from scripts.k8s import volume_snapshot

        empty_classes = '{"items": []}'

        ctx = mock_context(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "volumesnapshots", "-o", "json", "--all-namespaces"): volume_snapshots_healthy,
                ("kubectl", "get", "volumesnapshotcontents", "-o", "json"): volume_snapshot_contents_healthy,
                ("kubectl", "get", "volumesnapshotclasses", "-o", "json"): empty_classes,
            }
        )
        output = Output()

        exit_code = volume_snapshot.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["snapshotClasses"] == 0
