"""Tests for k8s job_status script."""

import json
from datetime import datetime, timezone, timedelta
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


def recent_timestamp(hours_ago: int = 1) -> str:
    """Generate a recent ISO timestamp."""
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestJobStatus:
    """Tests for job_status."""

    def get_jobs_healthy(self) -> dict:
        """Generate healthy jobs."""
        return {
            "items": [
                {
                    "metadata": {"name": "success-job", "namespace": "default"},
                    "spec": {"completions": 1, "parallelism": 1, "backoffLimit": 3},
                    "status": {
                        "succeeded": 1,
                        "failed": 0,
                        "active": 0,
                        "startTime": recent_timestamp(2),
                        "completionTime": recent_timestamp(1),
                        "conditions": [{"type": "Complete", "status": "True"}],
                    },
                }
            ]
        }

    def get_jobs_failed(self) -> dict:
        """Generate failed jobs."""
        return {
            "items": [
                {
                    "metadata": {"name": "failed-job", "namespace": "default"},
                    "spec": {"completions": 1, "backoffLimit": 3},
                    "status": {
                        "succeeded": 0,
                        "failed": 3,
                        "active": 0,
                        "startTime": recent_timestamp(2),
                        "conditions": [
                            {
                                "type": "Failed",
                                "status": "True",
                                "reason": "BackoffLimitExceeded",
                                "message": "Job has reached the specified backoff limit",
                            }
                        ],
                    },
                }
            ]
        }

    def get_cronjobs_healthy(self) -> dict:
        """Generate healthy CronJobs."""
        return {
            "items": [
                {
                    "metadata": {"name": "healthy-cron", "namespace": "default"},
                    "spec": {
                        "schedule": "0 * * * *",
                        "suspend": False,
                        "concurrencyPolicy": "Forbid",
                    },
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
                    "metadata": {"name": "stuck-cron", "namespace": "default"},
                    "spec": {
                        "schedule": "0 * * * *",
                        "suspend": False,
                        "concurrencyPolicy": "Forbid",
                    },
                    "status": {
                        "lastScheduleTime": recent_timestamp(1),
                        "active": [{"name": "job-1"}, {"name": "job-2"}],
                    },
                }
            ]
        }

    def test_all_healthy(self, capsys):
        """Healthy workloads return exit code 0."""
        from scripts.k8s.job_status import run

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

    def test_failed_jobs_detected(self, capsys):
        """Failed jobs return exit code 1."""
        from scripts.k8s.job_status import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_failed()
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "failed" in captured.out.lower()

    def test_cronjob_issues_detected(self, capsys):
        """CronJob issues return exit code 1."""
        from scripts.k8s.job_status import run

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
        assert "Multiple active jobs" in captured.out or "Forbid" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.job_status import run

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
        assert len(data["jobs"]) > 0
        assert "healthy" in data["jobs"][0]

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.job_status import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter restricts output."""
        from scripts.k8s.job_status import run

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

    def test_warn_only_filters(self, capsys):
        """Warn-only flag filters healthy jobs."""
        from scripts.k8s.job_status import run

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

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Healthy jobs should not be shown
        assert "success-job" not in captured.out or "WARNING" not in captured.out

    def test_failed_only_filters(self, capsys):
        """Failed-only flag filters healthy jobs."""
        from scripts.k8s.job_status import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_healthy()
                ),
                ("kubectl", "get", "cronjobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--failed-only"], output, context)

        assert result == 0

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.job_status import run

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

        assert "jobs_healthy=" in output.summary
        assert "cronjobs_healthy=" in output.summary
