"""Tests for cpu_throttling_detector script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "k8s"


def load_k8s_fixture(name: str) -> str:
    """Load a k8s fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestCpuThrottlingDetector:
    """Tests for cpu_throttling_detector."""

    def test_no_pods(self, capsys):
        """No pods returns exit code 0."""
        from scripts.k8s.cpu_throttling_detector import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_empty.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_pods_at_risk(self, capsys):
        """Pods at throttling risk returns exit code 1."""
        from scripts.k8s.cpu_throttling_detector import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_cpu_throttling.json"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "NAMESPACE" in captured.out or "AT RISK" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.k8s.cpu_throttling_detector import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_cpu_throttling.json"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "pods_at_risk" in data
        assert "pods" in data

    def test_warn_only_filter(self, capsys):
        """Warn-only filter shows only pods at risk."""
        from scripts.k8s.cpu_throttling_detector import run

        context = MockContext(
            tools_available=["kubectl"],
            command_outputs={
                ("kubectl", "get", "pods", "-o", "json", "--all-namespaces"): load_k8s_fixture(
                    "pods_cpu_throttling.json"
                ),
            },
        )
        output = Output()

        result = run(["--warn-only", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # All returned pods should be at risk
        for pod in data["pods"]:
            assert pod["risk"] == "AT RISK"

    def test_kubectl_not_found(self, capsys):
        """Missing kubectl returns exit code 2."""
        from scripts.k8s.cpu_throttling_detector import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_parse_cpu_value(self):
        """CPU values are parsed correctly."""
        from scripts.k8s.cpu_throttling_detector import parse_cpu_value

        assert parse_cpu_value("100m") == 100
        assert parse_cpu_value("1") == 1000
        assert parse_cpu_value("0.5") == 500
        assert parse_cpu_value("2000m") == 2000

    def test_low_cpu_limit_flagged(self):
        """Very low CPU limits are flagged as risky."""
        from scripts.k8s.cpu_throttling_detector import analyze_pod_throttling

        pod = {
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "resources": {
                            "limits": {"cpu": "50m"},
                            "requests": {"cpu": "25m"},
                        },
                    }
                ]
            }
        }

        has_limits, limit_m, is_at_risk, reason = analyze_pod_throttling(pod)

        assert has_limits is True
        assert limit_m == 50
        assert is_at_risk is True
        assert "low cpu limit" in reason.lower()

    def test_no_limits_flagged(self):
        """Pods without CPU limits/requests are flagged."""
        from scripts.k8s.cpu_throttling_detector import analyze_pod_throttling

        pod = {"spec": {"containers": [{"name": "app", "resources": {}}]}}

        has_limits, limit_m, is_at_risk, reason = analyze_pod_throttling(pod)

        assert has_limits is False
        assert is_at_risk is True
        assert "no cpu" in reason.lower()
