"""Tests for k8s workload_age script."""

import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestWorkloadAge:
    """Tests for workload_age."""

    def test_fresh_workloads(self, capsys):
        """Fresh workloads return exit code 0."""
        from scripts.k8s.workload_age import run

        now = datetime.now(timezone.utc)
        creation_time = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "fresh-pod",
                        "namespace": "default",
                        "creationTimestamp": creation_time,
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_stale_workloads(self, capsys):
        """Stale workloads return exit code 1."""
        from scripts.k8s.workload_age import run

        now = datetime.now(timezone.utc)
        creation_time = (now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "stale-pod",
                        "namespace": "default",
                        "creationTimestamp": creation_time,
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "STALE" in captured.out or "stale" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.workload_age import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "categories" in data
        assert "all_pods" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.workload_age import run

        now = datetime.now(timezone.utc)
        creation_time = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "test-pod",
                        "namespace": "default",
                        "creationTimestamp": creation_time,
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out
        assert "POD" in captured.out
        assert "AGE" in captured.out

    def test_namespace_filter(self, capsys):
        """Namespace filter is passed to kubectl."""
        from scripts.k8s.workload_age import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "-n", "production"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["-n", "production"], output, context)

        assert result == 0
        assert ("kubectl", "get", "pods", "-o", "json", "-n", "production") in [
            tuple(cmd) for cmd in context.commands_run
        ]

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.workload_age import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_custom_stale_days(self, capsys):
        """Custom stale-days threshold is respected."""
        from scripts.k8s.workload_age import run

        now = datetime.now(timezone.utc)
        creation_time = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "medium-age-pod",
                        "namespace": "default",
                        "creationTimestamp": creation_time,
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
            },
        )
        output = Output()

        # With default 30 days, should be OK
        result = run([], output, context)
        assert result == 0

        # With 7 days threshold, should be stale
        result = run(["--stale-days", "7"], output, context)
        assert result == 1

    def test_exclude_namespace(self, capsys):
        """Exclude-namespace flag filters namespaces."""
        from scripts.k8s.workload_age import run

        now = datetime.now(timezone.utc)
        old_time = (now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "stale-pod",
                        "namespace": "kube-system",
                        "creationTimestamp": old_time,
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
            },
        )
        output = Output()

        result = run(["--exclude-namespace", "kube-system"], output, context)

        # Should be 0 because the stale pod is excluded
        assert result == 0

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.workload_age import run

        now = datetime.now(timezone.utc)
        creation_time = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

        pods_data = {
            "items": [
                {
                    "metadata": {
                        "name": "test-pod",
                        "namespace": "default",
                        "creationTimestamp": creation_time,
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"restartCount": 0}
                        ],
                    },
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): json.dumps(
                    pods_data
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "pods=" in output.summary or "stale=" in output.summary
