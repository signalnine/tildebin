"""Tests for k8s webhook_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestWebhookHealth:
    """Tests for webhook_health."""

    def test_no_webhooks(self, capsys):
        """No webhooks returns exit code 0."""
        from scripts.k8s.webhook_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_healthy_webhook(self, capsys):
        """Healthy webhook returns exit code 0."""
        from scripts.k8s.webhook_health import run

        validating_data = {
            "items": [
                {
                    "metadata": {"name": "test-webhook"},
                    "webhooks": [
                        {
                            "name": "test.webhook.io",
                            "failurePolicy": "Fail",
                            "timeoutSeconds": 10,
                            "sideEffects": "None",
                            "admissionReviewVersions": ["v1", "v1beta1"],
                            "clientConfig": {
                                "service": {
                                    "name": "webhook-service",
                                    "namespace": "default",
                                    "port": 443,
                                }
                            },
                            "rules": [
                                {
                                    "operations": ["CREATE"],
                                    "resources": ["pods"],
                                }
                            ],
                            "objectSelector": {"matchLabels": {"app": "test"}},
                        }
                    ],
                }
            ]
        }

        service_data = {
            "spec": {"clusterIP": "10.0.0.1"},
        }

        endpoints_data = {
            "subsets": [
                {"addresses": [{"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}]}
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    validating_data
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "service", "webhook-service", "-n", "default", "-o", "json"): json.dumps(
                    service_data
                ),
                ("kubectl", "get", "endpoints", "webhook-service", "-n", "default", "-o", "json"): json.dumps(
                    endpoints_data
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_fail_open_warning(self, capsys):
        """Fail-open webhook generates warning."""
        from scripts.k8s.webhook_health import run

        validating_data = {
            "items": [
                {
                    "metadata": {"name": "test-webhook"},
                    "webhooks": [
                        {
                            "name": "test.webhook.io",
                            "failurePolicy": "Ignore",
                            "timeoutSeconds": 10,
                            "sideEffects": "None",
                            "admissionReviewVersions": ["v1"],
                            "clientConfig": {},
                            "objectSelector": {"matchLabels": {"app": "test"}},
                        }
                    ],
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    validating_data
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--no-endpoint-check"], output, context)

        captured = capsys.readouterr()
        assert "Ignore" in captured.out or "fail-open" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.webhook_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "summary" in data
        assert "webhooks" in data
        assert "issues" in data
        assert "warnings" in data
        assert "healthy" in data

    def test_table_output(self, capsys):
        """Table output includes header."""
        from scripts.k8s.webhook_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "Webhook Health Check" in captured.out

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.webhook_health import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_service_unavailable(self, capsys):
        """Unavailable service endpoint generates issue."""
        from scripts.k8s.webhook_health import run

        validating_data = {
            "items": [
                {
                    "metadata": {"name": "test-webhook"},
                    "webhooks": [
                        {
                            "name": "test.webhook.io",
                            "failurePolicy": "Fail",
                            "timeoutSeconds": 10,
                            "sideEffects": "None",
                            "admissionReviewVersions": ["v1"],
                            "clientConfig": {
                                "service": {
                                    "name": "missing-service",
                                    "namespace": "default",
                                    "port": 443,
                                }
                            },
                            "objectSelector": {"matchLabels": {"app": "test"}},
                        }
                    ],
                }
            ]
        }

        # Mock command that returns non-zero for missing service
        class MockResult:
            def __init__(self):
                self.returncode = 1
                self.stdout = ""
                self.stderr = "not found"

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    validating_data
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )

        # Override run to return failure for service lookup
        original_run = context.run

        def mock_run(cmd, **kwargs):
            if "service" in cmd and "missing-service" in cmd:
                result = type("Result", (), {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "not found"
                })()
                return result
            return original_run(cmd, **kwargs)

        context.run = mock_run
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_summary_set(self, capsys):
        """Summary is set correctly."""
        from scripts.k8s.webhook_health import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        run([], output, context)

        assert "issues=" in output.summary
        assert "warnings=" in output.summary

    def test_no_endpoint_check_flag(self, capsys):
        """No-endpoint-check flag skips endpoint checks."""
        from scripts.k8s.webhook_health import run

        validating_data = {
            "items": [
                {
                    "metadata": {"name": "test-webhook"},
                    "webhooks": [
                        {
                            "name": "test.webhook.io",
                            "failurePolicy": "Fail",
                            "timeoutSeconds": 10,
                            "sideEffects": "None",
                            "admissionReviewVersions": ["v1"],
                            "clientConfig": {
                                "service": {
                                    "name": "webhook-service",
                                    "namespace": "default",
                                    "port": 443,
                                }
                            },
                            "objectSelector": {"matchLabels": {"app": "test"}},
                        }
                    ],
                }
            ]
        }

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "validatingwebhookconfigurations", "-o", "json"): json.dumps(
                    validating_data
                ),
                ("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"): json.dumps(
                    {"items": []}
                ),
            },
        )
        output = Output()

        result = run(["--no-endpoint-check"], output, context)

        # Should not try to get service/endpoints
        cmd_strs = [" ".join(cmd) for cmd in context.commands_run]
        assert not any("service" in cmd for cmd in cmd_strs)
