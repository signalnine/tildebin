"""Tests for k8s backup_health script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestBackupHealth:
    """Tests for backup_health."""

    def test_no_backup_systems(self, capsys):
        """No backup systems returns exit code 0."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                # Velero not installed
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=velero.io",
                    "-o",
                    "name",
                ): "",
                # VolumeSnapshots not installed
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=snapshot.storage.k8s.io",
                    "-o",
                    "name",
                ): "",
                # No backup-related CronJobs
                ("kubectl", "get", "cronjobs", "-o", "json", "-A"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No backup systems detected" in captured.out

    def test_healthy_velero_backups(self, capsys):
        """Healthy Velero backups return exit code 0."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=velero.io",
                    "-o",
                    "name",
                ): "backups.velero.io\nschedules.velero.io",
                (
                    "kubectl",
                    "get",
                    "schedules.velero.io",
                    "-A",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "backups.velero.io",
                    "-A",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {
                                    "name": "daily-backup-20240101",
                                    "namespace": "velero",
                                },
                                "status": {
                                    "phase": "Completed",
                                    "completionTimestamp": "2024-01-01T12:00:00Z",
                                },
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=snapshot.storage.k8s.io",
                    "-o",
                    "name",
                ): "",
                ("kubectl", "get", "cronjobs", "-o", "json", "-A"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        # Use large max-age to ensure backup is not considered stale
        result = run(["--max-age", "87600"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Velero Backups" in captured.out
        assert "daily-backup-20240101" in captured.out

    def test_failed_velero_backup(self, capsys):
        """Failed Velero backup returns exit code 1."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=velero.io",
                    "-o",
                    "name",
                ): "backups.velero.io",
                (
                    "kubectl",
                    "get",
                    "schedules.velero.io",
                    "-A",
                    "-o",
                    "json",
                ): json.dumps({"items": []}),
                (
                    "kubectl",
                    "get",
                    "backups.velero.io",
                    "-A",
                    "-o",
                    "json",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {
                                    "name": "failed-backup",
                                    "namespace": "velero",
                                },
                                "status": {
                                    "phase": "Failed",
                                    "failureReason": "Volume snapshot error",
                                },
                            }
                        ]
                    }
                ),
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=snapshot.storage.k8s.io",
                    "-o",
                    "name",
                ): "",
                ("kubectl", "get", "cronjobs", "-o", "json", "-A"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "failed-backup" in captured.out
        assert "Failed" in captured.out

    def test_healthy_volume_snapshots(self, capsys):
        """Healthy VolumeSnapshots return exit code 0."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=velero.io",
                    "-o",
                    "name",
                ): "",
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=snapshot.storage.k8s.io",
                    "-o",
                    "name",
                ): "volumesnapshots.snapshot.storage.k8s.io",
                (
                    "kubectl",
                    "get",
                    "volumesnapshots",
                    "-o",
                    "json",
                    "-A",
                ): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {
                                    "name": "pvc-snapshot",
                                    "namespace": "default",
                                    "creationTimestamp": "2024-01-01T12:00:00Z",
                                },
                                "status": {
                                    "readyToUse": True,
                                    "restoreSize": "10Gi",
                                },
                            }
                        ]
                    }
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "-A"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        # Use large max-age to ensure snapshot is not considered stale
        result = run(["--max-age", "87600"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "VolumeSnapshots" in captured.out
        assert "pvc-snapshot" in captured.out

    def test_backup_cronjob_detection(self, capsys):
        """Backup-related CronJobs are detected."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=velero.io",
                    "-o",
                    "name",
                ): "",
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=snapshot.storage.k8s.io",
                    "-o",
                    "name",
                ): "",
                ("kubectl", "get", "cronjobs", "-o", "json", "-A"): json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {
                                    "name": "etcd-backup",
                                    "namespace": "kube-system",
                                },
                                "spec": {
                                    "schedule": "0 2 * * *",
                                    "suspend": False,
                                },
                                "status": {
                                    "lastScheduleTime": "2024-01-01T02:00:00Z",
                                    "lastSuccessfulTime": "2024-01-01T02:05:00Z",
                                },
                            },
                            {
                                "metadata": {
                                    "name": "some-other-job",
                                    "namespace": "default",
                                },
                                "spec": {
                                    "schedule": "* * * * *",
                                },
                                "status": {},
                            },
                        ]
                    }
                ),
            },
        )
        output = Output()

        # Use large max-age to ensure cronjob is not considered stale
        result = run(["--max-age", "87600"], output, context)

        captured = capsys.readouterr()
        # Should detect etcd-backup but not some-other-job
        assert "etcd-backup" in captured.out
        assert "some-other-job" not in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=velero.io",
                    "-o",
                    "name",
                ): "",
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=snapshot.storage.k8s.io",
                    "-o",
                    "name",
                ): "",
                ("kubectl", "get", "cronjobs", "-o", "json", "-A"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "velero" in data
        assert "volumesnapshots" in data
        assert "cronjobs" in data
        assert "summary" in data
        assert "healthy" in data["summary"]

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.backup_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=velero.io",
                    "-o",
                    "name",
                ): "",
                (
                    "kubectl",
                    "api-resources",
                    "--api-group=snapshot.storage.k8s.io",
                    "-o",
                    "name",
                ): "",
                ("kubectl", "get", "cronjobs", "-o", "json", "-A"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "velero=" in output.summary
        assert "snapshots=" in output.summary
        assert "cronjobs=" in output.summary
        assert "healthy=" in output.summary
