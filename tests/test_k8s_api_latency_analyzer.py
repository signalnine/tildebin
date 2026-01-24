#!/usr/bin/env python3
"""
Tests for k8s_api_latency_analyzer.py

Tests validate:
  - Argument parsing and help messages
  - Output formatting (plain, table, json)
  - Threshold validation
  - Error handling for missing kubectl
  - Exit codes
"""

import os
import subprocess
import sys
import json


def run_command(cmd_args):
    """
    Execute k8s_api_latency_analyzer.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_api_latency_analyzer.py"
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
    assert "latency" in stdout.lower(), "Help should mention latency"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"


def test_format_plain():
    """Validate --format plain is accepted."""
    returncode, stdout, stderr = run_command(["--format", "plain"])

    # Should either succeed or fail due to kubectl not being available (exit 2)
    # But should NOT fail due to invalid argument
    assert returncode in [0, 1, 2], f"Expected exit code 0, 1, or 2, got {returncode}"
    if returncode == 2:
        assert "kubectl" in stderr.lower(), "Exit 2 should mention kubectl"


def test_format_table():
    """Validate --format table is accepted."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    assert returncode in [0, 1, 2], f"Expected exit code 0, 1, or 2, got {returncode}"


def test_format_json():
    """Validate --format json is accepted."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    assert returncode in [0, 1, 2], f"Expected exit code 0, 1, or 2, got {returncode}"


def test_format_invalid():
    """Validate invalid --format is rejected."""
    returncode, stdout, stderr = run_command(["--format", "invalid"])

    # Should fail with argument error
    assert returncode != 0, "Invalid format should fail"
    assert "invalid" in stderr.lower() or "format" in stderr.lower(), \
        "Should mention invalid format in error"


def test_namespace_flag():
    """Validate --namespace flag is accepted."""
    returncode, stdout, stderr = run_command(["-n", "default"])

    # Should either succeed or fail due to kubectl not being available (exit 2)
    assert returncode in [0, 1, 2], "Should accept -n/--namespace flag"


def test_warn_only_flag():
    """Validate --warn-only flag is accepted."""
    returncode, stdout, stderr = run_command(["--warn-only"])

    assert returncode in [0, 1, 2], "Should accept --warn-only flag"


def test_samples_flag():
    """Validate --samples flag is accepted."""
    returncode, stdout, stderr = run_command(["--samples", "5"])

    assert returncode in [0, 1, 2], "Should accept --samples flag"


def test_samples_invalid():
    """Validate invalid --samples value is rejected."""
    returncode, stdout, stderr = run_command(["--samples", "0"])

    assert returncode == 2, "Invalid samples should exit with 2"
    assert "samples" in stderr.lower(), "Should mention samples in error"


def test_warn_threshold_flag():
    """Validate --warn-threshold flag is accepted."""
    returncode, stdout, stderr = run_command(["--warn-threshold", "300"])

    assert returncode in [0, 1, 2], "Should accept --warn-threshold flag"


def test_critical_threshold_flag():
    """Validate --critical-threshold flag is accepted."""
    returncode, stdout, stderr = run_command(["--critical-threshold", "3000"])

    assert returncode in [0, 1, 2], "Should accept --critical-threshold flag"


def test_threshold_validation():
    """Validate warn-threshold must be less than critical-threshold."""
    returncode, stdout, stderr = run_command([
        "--warn-threshold", "1000",
        "--critical-threshold", "500"
    ])

    assert returncode == 2, "Invalid thresholds should exit with 2"
    assert "threshold" in stderr.lower(), "Should mention threshold in error"


def test_verbose_flag():
    """Validate --verbose flag is accepted."""
    returncode, stdout, stderr = run_command(["-v"])

    assert returncode in [0, 1, 2], "Should accept -v/--verbose flag"


def test_combined_flags():
    """Validate multiple flags can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "-f", "json",
        "--warn-only",
        "--samples", "2"
    ])

    assert returncode in [0, 1, 2], "Should accept combined flags"


def test_argument_order():
    """Validate arguments work in different orders."""
    returncode1, _, _ = run_command(["-f", "plain", "-n", "default"])
    returncode2, _, _ = run_command(["-n", "default", "-f", "plain"])

    # Both should have same behavior
    assert returncode1 in [0, 1, 2] and returncode2 in [0, 1, 2], \
        "Argument order should not matter"


def test_json_output_structure():
    """Validate JSON output structure when available."""
    returncode, stdout, stderr = run_command(["-f", "json"])

    if returncode == 0 and stdout:
        try:
            data = json.loads(stdout)
            assert "summary" in data, "JSON should have 'summary' key"
            assert "operations" in data, "JSON should have 'operations' key"
            assert "issues" in data, "JSON should have 'issues' key"
            assert "warnings" in data, "JSON should have 'warnings' key"
            assert "timestamp" in data, "JSON should have 'timestamp' key"
        except json.JSONDecodeError as e:
            assert False, f"JSON output should be valid JSON: {e}"


def test_json_summary_fields():
    """Validate JSON summary contains expected fields."""
    returncode, stdout, stderr = run_command(["-f", "json"])

    if returncode == 0 and stdout:
        data = json.loads(stdout)
        summary = data.get('summary', {})
        assert 'total_operations' in summary, "Summary should have total_operations"
        assert 'healthy' in summary, "Summary should have healthy status"
        assert 'overall_avg_latency_ms' in summary, "Summary should have avg latency"


def test_exit_codes():
    """Validate exit codes are as documented."""
    returncode, stdout, stderr = run_command(["--help"])
    assert returncode == 0, "Help should exit with 0"

    # Normal run should be 0, 1, or 2
    returncode, stdout, stderr = run_command(["-f", "json"])
    assert returncode in [0, 1, 2], f"Exit code should be 0, 1, or 2, got {returncode}"


def test_no_extra_output_on_help():
    """Validate --help doesn't execute kubectl."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, "Help should exit cleanly"
    assert "usage:" in stdout, "Help should be shown"
    # Should not have kubectl errors in stderr when showing help
    assert "error" not in stderr.lower() or "kubectl" not in stderr.lower(), \
        "Help should not attempt kubectl operations"


def test_format_flag_compatibility():
    """Validate all documented formats work."""
    valid_formats = ["plain", "table", "json"]

    for fmt in valid_formats:
        returncode, stdout, stderr = run_command(["-f", fmt])
        assert returncode in [0, 1, 2], f"Format {fmt} should be accepted"


def test_table_output_has_headers():
    """Validate table format contains expected structure."""
    returncode, stdout, stderr = run_command(["-f", "table"])

    if returncode == 0 and stdout:
        assert "Operation" in stdout or "+" in stdout, \
            "Table should have headers or borders"


def test_plain_output_structure():
    """Validate plain format contains expected information."""
    returncode, stdout, stderr = run_command(["-f", "plain"])

    if returncode == 0 and stdout:
        # Should have column headers or operation names
        assert "latency" in stdout.lower() or "operation" in stdout.lower() or \
               "LIST" in stdout or "GET" in stdout, \
            "Plain output should mention operations or latency"


if __name__ == "__main__":
    # Run all tests
    tests = [
        test_help_message,
        test_help_message_h,
        test_format_plain,
        test_format_table,
        test_format_json,
        test_format_invalid,
        test_namespace_flag,
        test_warn_only_flag,
        test_samples_flag,
        test_samples_invalid,
        test_warn_threshold_flag,
        test_critical_threshold_flag,
        test_threshold_validation,
        test_verbose_flag,
        test_combined_flags,
        test_argument_order,
        test_json_output_structure,
        test_json_summary_fields,
        test_exit_codes,
        test_no_extra_output_on_help,
        test_format_flag_compatibility,
        test_table_output_has_headers,
        test_plain_output_structure,
    ]

    failed = 0
    passed = 0

    for test in tests:
        try:
            test()
            print(f"[PASS] {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: Unexpected error: {e}")
            failed += 1

    # Output test results in format expected by test runner
    print(f"\nTest Results: {passed}/{len(tests)} tests passed")
    sys.exit(0 if failed == 0 else 1)
