"""Tests for k8s job_health script."""

import json
from datetime import datetime, timezone, timedelta
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


def recent_timestamp(hours_ago: int = 1) -> str:
    """Generate a recent ISO timestamp."""
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestJobHealth:
    """Tests for job_health."""

    def get_jobs_healthy(self) -> dict:
        """Generate healthy jobs."""
        return {
            "items": [
                {
                    "metadata": {
                        "name": "success-job",
                        "namespace": "default",
                        "creationTimestamp": recent_timestamp(2),
                    },
                    "spec": {"ttlSecondsAfterFinished": 3600},
                    "status": {
                        "succeeded": 1,
                        "startTime": recent_timestamp(2),
                        "completionTime": recent_timestamp(1),
                    },
                }
            ]
        }

    def get_jobs_with_issues(self) -> dict:
        """Generate jobs with issues."""
        return {
            "items": [
                {
                    "metadata": {
                        "name": "failed-job",
                        "namespace": "default",
                        "creationTimestamp": recent_timestamp(2),
                    },
                    "spec": {},
                    "status": {"failed": 3},
                }
            ]
        }

    def get_cronjobs_healthy(self) -> dict:
        """Generate healthy CronJobs."""
        return {
            "items": [
                {
                    "metadata": {"name": "healthy-cron", "namespace": "default"},
                    "spec": {"schedule": "0 * * * *", "suspend": False},
                    "status": {
                        "lastScheduleTime": recent_timestamp(1),
                        "lastSuccessfulTime": recent_timestamp(1),
                        "active": [],
                    },
                }
            ]
        }

    def get_cronjobs_with_issues(self) -> dict:
        """Generate CronJobs with issues."""
        return {
            "items": [
                {
                    "metadata": {"name": "suspended-cron", "namespace": "default"},
                    "spec": {"schedule": "0 * * * *", "suspend": True},
                    "status": {"active": []},
                }
            ]
        }

    def test_all_healthy(self, capsys):
        """Healthy workloads return exit code 0."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_healthy()
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_cronjobs_healthy()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_job_issues_detected(self, capsys):
        """Job issues return exit code 1."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_with_issues()
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_cronjob_issues_detected(self, capsys):
        """CronJob issues return exit code 1."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_cronjobs_with_issues()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "suspended" in captured.out.lower() or "cronjobs_with_issues=1" in output.summary

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_healthy()
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_cronjobs_healthy()
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "jobs" in data
        assert "cronjobs" in data
        assert "summary" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_healthy()
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_cronjobs_healthy()
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Namespace" in captured.out
        assert "Name" in captured.out
        assert "Status" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter restricts output."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0

    def test_skip_jobs(self, capsys):
        """Skip jobs flag works."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_cronjobs_healthy()
                ),
            },
        )
        output = Output()

        result = run(["--skip-jobs"], output, context)

        assert result == 0

    def test_skip_cronjobs(self, capsys):
        """Skip cronjobs flag works."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_healthy()
                ),
            },
        )
        output = Output()

        result = run(["--skip-cronjobs"], output, context)

        assert result == 0

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.job_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "jobs=" in output.summary
        assert "cronjobs=" in output.summary
