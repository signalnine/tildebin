"""Tests for k8s job_failures script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestJobFailures:
    """Tests for job_failures."""

    def get_jobs_with_failures(self) -> dict:
        """Generate jobs with failures."""
        return {
            "items": [
                {
                    "metadata": {
                        "name": "failed-job",
                        "namespace": "default",
                        "ownerReferences": [],
                    },
                    "spec": {"backoffLimit": 3},
                    "status": {
                        "failed": 3,
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

    def get_jobs_healthy(self) -> dict:
        """Generate healthy jobs."""
        return {
            "items": [
                {
                    "metadata": {"name": "success-job", "namespace": "default"},
                    "spec": {"backoffLimit": 3},
                    "status": {
                        "succeeded": 1,
                        "conditions": [
                            {"type": "Complete", "status": "True"}
                        ],
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
                    "spec": {"suspend": True, "schedule": "0 * * * *"},
                    "status": {},
                }
            ]
        }

    def test_no_failures(self, capsys):
        """No failures returns exit code 0."""
        from scripts.k8s.job_failures import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_healthy()
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_failures_detected(self, capsys):
        """Job failures return exit code 1."""
        from scripts.k8s.job_failures import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_with_failures()
                ),
                ("kubectl", "get", "pods", "-n", "default", "-l", "job-name=failed-job", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "BackoffLimitExceeded" in captured.out or "failed_jobs=1" in output.summary

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.job_failures import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_with_failures()
                ),
                ("kubectl", "get", "pods", "-n", "default", "-l", "job-name=failed-job", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_failed" in data
        assert "failed_jobs" in data
        assert "by_category" in data

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.job_failures import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_namespace_filter(self, capsys):
        """Namespace filter restricts output."""
        from scripts.k8s.job_failures import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0

    def test_include_cronjobs(self, capsys):
        """Include CronJobs flag works."""
        from scripts.k8s.job_failures import run

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

        result = run(["--include-cronjobs"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Suspended" in captured.out or "cronjob_issues=1" in output.summary

    def test_verbose_output(self, capsys):
        """Verbose output shows remediation."""
        from scripts.k8s.job_failures import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    self.get_jobs_with_failures()
                ),
                ("kubectl", "get", "pods", "-n", "default", "-l", "job-name=failed-job", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Remediation" in captured.out

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.job_failures import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "jobs", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "failed_jobs=" in output.summary
        assert "cronjob_issues=" in output.summary
