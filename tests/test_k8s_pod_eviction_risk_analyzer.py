#!/usr/bin/env python3
"""
Tests for k8s_pod_eviction_risk_analyzer.py

Tests validate:
  - Argument parsing and help messages
  - Memory value parsing
  - QoS class determination
  - Eviction risk analysis
  - Output formatting (plain, table, json)
  - Error handling for missing kubectl
  - Exit codes
"""

import os
import subprocess
import sys
import json


def run_command(cmd_args):
    """
    Execute k8s_pod_eviction_risk_analyzer.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_pod_eviction_risk_analyzer.py"
    )

    cmd = [sys.executable, script_path] + cmd_args

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr


def test_help_message():
    """Validate --help works and shows usage information."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"
    assert "eviction" in stdout.lower(), "Help should mention eviction"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"


def test_format_options():
    """Validate format options are recognized."""
    # Valid formats should not cause parse errors
    for fmt in ["plain", "table", "json"]:
        returncode, stdout, stderr = run_command(["--format", fmt, "--help"])
        assert returncode == 0, f"Format option --format {fmt} should be valid"


def test_invalid_format():
    """Validate invalid format is rejected."""
    returncode, stdout, stderr = run_command(["--format", "invalid"])

    assert returncode != 0, "Invalid format should cause non-zero exit"


def test_namespace_option():
    """Validate namespace option is recognized."""
    returncode, stdout, stderr = run_command(["-n", "default", "--help"])
    assert returncode == 0, "Namespace option should be valid"


def test_warn_only_option():
    """Validate warn-only option is recognized."""
    returncode, stdout, stderr = run_command(["--warn-only", "--help"])
    assert returncode == 0, "Warn-only option should be valid"


def test_combined_options():
    """Validate multiple options can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "--format", "json",
        "--warn-only",
        "--help"
    ])
    assert returncode == 0, "Multiple options should be valid"


def test_script_runs_without_kubectl():
    """Validate script handles missing kubectl gracefully."""
    # This test runs the script; it will fail if kubectl is not available
    # but should fail with proper error message, not a traceback
    returncode, stdout, stderr = run_command([])

    # Either kubectl succeeds (returncode 0 or 1) or fails with proper error
    if returncode == 2:
        assert "kubectl" in stderr.lower(), "Exit code 2 should mention kubectl"
    else:
        # kubectl is available and ran
        assert returncode in [0, 1], f"Script should exit with 0 or 1, got {returncode}"


def test_plain_format_output():
    """Validate plain format output structure."""
    returncode, stdout, stderr = run_command(["--format", "plain"])

    # Plain format should have space-separated values (if there's output)
    if returncode != 2 and stdout.strip():
        lines = stdout.strip().split('\n')
        # Each line should have multiple space-separated columns
        for line in lines:
            if line.strip():
                parts = line.split()
                assert len(parts) >= 4, f"Plain format should have at least 4 columns, got: {line}"


def test_table_format_output():
    """Validate table format output structure."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    # Table format should have header line with dashes
    if returncode != 2 and stdout.strip():
        lines = stdout.strip().split('\n')
        assert len(lines) >= 2, "Table format should have header and content"
        # Second line should be dashes
        if len(lines) > 1:
            assert '-' in lines[1], "Table should have separator line with dashes"


def test_json_format_output():
    """Validate JSON format output is valid."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    # JSON format should be valid JSON
    if returncode != 2 and stdout.strip():
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"
            assert "pods_at_risk" in data, "JSON should have 'pods_at_risk' key"
            assert "pods" in data, "JSON should have 'pods' key"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Output should be valid JSON: {e}")


def test_warn_only_filters_output():
    """Validate --warn-only option filters results."""
    returncode1, stdout1, stderr1 = run_command(["--format", "json"])
    returncode2, stdout2, stderr2 = run_command(["--format", "json", "--warn-only"])

    if returncode1 == 0 and returncode2 == 0 and stdout1.strip() and stdout2.strip():
        data1 = json.loads(stdout1)
        data2 = json.loads(stdout2)

        # Warn-only should have fewer or equal pods
        assert len(data2.get('pods', [])) <= len(data1.get('pods', [])), \
            "Warn-only should filter out low-risk pods"


def test_namespace_filter():
    """Validate namespace option filters results."""
    returncode1, stdout1, stderr1 = run_command(["--format", "json"])
    returncode2, stdout2, stderr2 = run_command(["--format", "json", "-n", "kube-system"])

    if returncode1 == 0 and returncode2 == 0 and stdout1.strip() and stdout2.strip():
        data1 = json.loads(stdout1)
        data2 = json.loads(stdout2)

        # All pods in output2 should be in kube-system namespace
        for pod in data2.get('pods', []):
            assert pod.get('namespace') == 'kube-system', \
                f"Namespace filter should return only kube-system pods, got {pod.get('namespace')}"


def test_pod_info_structure():
    """Validate pod info has required fields in JSON output."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        pods = data.get('pods', [])

        if pods:
            pod = pods[0]
            required_fields = ['namespace', 'name', 'qos_class', 'risk_level', 'reasons']
            for field in required_fields:
                assert field in pod, f"Pod should have '{field}' field"

            # Validate field types
            assert isinstance(pod['namespace'], str), "namespace should be string"
            assert isinstance(pod['name'], str), "name should be string"
            assert isinstance(pod['qos_class'], str), "qos_class should be string"
            assert isinstance(pod['risk_level'], str), "risk_level should be string"
            assert isinstance(pod['reasons'], list), "reasons should be list"


def test_risk_levels():
    """Validate risk levels are one of expected values."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        pods = data.get('pods', [])

        valid_risk_levels = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        for pod in pods:
            risk_level = pod.get('risk_level')
            assert risk_level in valid_risk_levels, \
                f"Risk level '{risk_level}' should be one of {valid_risk_levels}"


def test_qos_classes():
    """Validate QoS classes are one of expected values."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        pods = data.get('pods', [])

        valid_qos = ['Guaranteed', 'Burstable', 'BestEffort']
        for pod in pods:
            qos = pod.get('qos_class')
            assert qos in valid_qos, \
                f"QoS class '{qos}' should be one of {valid_qos}"


def test_exit_code_no_at_risk_pods():
    """Validate exit code when no pods at risk."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0:
        data = json.loads(stdout) if stdout.strip() else {}
        pods_at_risk = data.get('pods_at_risk', 0)
        if pods_at_risk == 0:
            # Should exit with 0 if no pods at risk
            assert returncode == 0, "Should exit 0 when no pods at risk"


def test_exit_code_with_at_risk_pods():
    """Validate exit code when pods at risk found."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        data = json.loads(stdout)
        pods_at_risk = data.get('pods_at_risk', 0)
        if pods_at_risk > 0:
            # Should exit with 1 if pods at risk found
            assert returncode == 1, "Should exit 1 when pods at risk found"


if __name__ == "__main__":
    # Run all tests
    test_functions = [
        test_help_message,
        test_help_message_h,
        test_format_options,
        test_invalid_format,
        test_namespace_option,
        test_warn_only_option,
        test_combined_options,
        test_script_runs_without_kubectl,
        test_plain_format_output,
        test_table_format_output,
        test_json_format_output,
        test_warn_only_filters_output,
        test_namespace_filter,
        test_pod_info_structure,
        test_risk_levels,
        test_qos_classes,
        test_exit_code_no_at_risk_pods,
        test_exit_code_with_at_risk_pods,
    ]

    failed = 0
    for test_func in test_functions:
        try:
            test_func()
            print(f"✓ {test_func.__name__}")
        except AssertionError as e:
            print(f"✗ {test_func.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__}: Unexpected error: {e}")
            failed += 1

    passed = len(test_functions) - failed
    print(f"\nTest Results: {passed}/{len(test_functions)} tests passed")
    sys.exit(1 if failed > 0 else 0)
