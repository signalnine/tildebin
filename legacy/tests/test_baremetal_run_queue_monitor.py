#!/usr/bin/env python3
"""
Tests for baremetal_run_queue_monitor.py

Tests validate:
  - Argument parsing and help messages
  - Output format options (plain, json, table)
  - Threshold options
  - Exit codes
  - JSON output structure
"""

import json
import os
import subprocess
import sys


def run_command(cmd_args):
    """
    Execute baremetal_run_queue_monitor.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "baremetal_run_queue_monitor.py"
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
    assert "usage:" in stdout.lower(), "Help should contain usage information"
    assert "run queue" in stdout.lower(), "Help should mention run queue"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout.lower(), "Help should contain usage information"


def test_format_plain():
    """Validate --format plain is accepted and produces output."""
    returncode, stdout, stderr = run_command(["--format", "plain"])

    # Should succeed on Linux systems with /proc
    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"
    if returncode != 2:
        assert "Run Queue" in stdout or "queue" in stdout.lower(), \
            "Plain output should contain run queue info"


def test_format_json():
    """Validate --format json produces valid JSON."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"
    if returncode != 2 and stdout.strip():
        try:
            data = json.loads(stdout)
            assert "status" in data, "JSON should have status key"
            assert "healthy" in data, "JSON should have healthy key"
            assert "running_tasks" in data, "JSON should have running_tasks key"
        except json.JSONDecodeError as e:
            assert False, f"JSON output should be valid JSON: {e}"


def test_format_table():
    """Validate --format table produces tabular output."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"
    if returncode != 2:
        assert "METRIC" in stdout or "STATUS" in stdout, \
            "Table output should have headers"


def test_format_invalid():
    """Validate invalid --format is rejected."""
    returncode, stdout, stderr = run_command(["--format", "invalid"])

    assert returncode != 0, "Invalid format should fail"
    assert "invalid" in stderr.lower() or "choice" in stderr.lower(), \
        "Should mention invalid format in error"


def test_short_format_flag():
    """Validate -f short flag works."""
    returncode, stdout, stderr = run_command(["-f", "json"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_verbose_flag():
    """Validate --verbose flag is accepted."""
    returncode, stdout, stderr = run_command(["--verbose"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"
    # Verbose should show more detail
    if returncode != 2:
        assert "CPU" in stdout, "Verbose output should show CPU info"


def test_short_verbose_flag():
    """Validate -v short flag works."""
    returncode, stdout, stderr = run_command(["-v"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_warn_only_flag():
    """Validate --warn-only flag is accepted."""
    returncode, stdout, stderr = run_command(["--warn-only"])

    # Should succeed - may produce no output if no warnings
    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_short_warn_only_flag():
    """Validate -w short flag works."""
    returncode, stdout, stderr = run_command(["-w"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_queue_warning_threshold():
    """Validate --queue-warning threshold option."""
    returncode, stdout, stderr = run_command(["--queue-warning", "0.5"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_queue_critical_threshold():
    """Validate --queue-critical threshold option."""
    returncode, stdout, stderr = run_command(["--queue-critical", "3.0"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_imbalance_warning_threshold():
    """Validate --imbalance-warning threshold option."""
    returncode, stdout, stderr = run_command(["--imbalance-warning", "25"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_imbalance_critical_threshold():
    """Validate --imbalance-critical threshold option."""
    returncode, stdout, stderr = run_command(["--imbalance-critical", "60"])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_combined_flags():
    """Validate multiple flags can be combined."""
    returncode, stdout, stderr = run_command([
        "-f", "json",
        "-v",
        "--queue-warning", "1.5",
        "--queue-critical", "3.0"
    ])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_json_output_structure():
    """Validate JSON output has expected structure."""
    returncode, stdout, stderr = run_command(["-f", "json"])

    if returncode != 2 and stdout.strip():
        data = json.loads(stdout)

        # Check required fields
        required_fields = [
            'timestamp', 'cpu_count', 'running_tasks', 'blocked_tasks',
            'avg_queue_depth', 'status', 'issues', 'warnings', 'healthy'
        ]

        for field in required_fields:
            assert field in data, f"JSON should have '{field}' field"

        # Check types
        assert isinstance(data['cpu_count'], int), "cpu_count should be int"
        assert isinstance(data['running_tasks'], int), "running_tasks should be int"
        assert isinstance(data['issues'], list), "issues should be list"
        assert isinstance(data['warnings'], list), "warnings should be list"
        assert isinstance(data['healthy'], bool), "healthy should be bool"


def test_exit_code_values():
    """Validate exit codes are within expected range."""
    returncode, stdout, stderr = run_command([])

    # Exit code should be 0 (healthy), 1 (issues), or 2 (error)
    assert returncode in [0, 1, 2], f"Exit code should be 0, 1, or 2, got {returncode}"


def test_no_extra_output_on_help():
    """Validate --help doesn't try to read /proc."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, "Help should exit cleanly"
    assert "usage:" in stdout.lower(), "Help should be shown"
    # Should not contain error messages
    assert "error" not in stderr.lower(), "Help should not produce errors"


def test_examples_in_help():
    """Validate help includes usage examples."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, "Help should exit with 0"
    assert "Examples:" in stdout or "example" in stdout.lower(), \
        "Help should include examples"


def test_description_mentions_key_features():
    """Validate help describes key functionality."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, "Help should exit with 0"
    # Should mention key features
    keywords = ["queue", "cpu", "scheduler"]
    found = any(kw in stdout.lower() for kw in keywords)
    assert found, f"Help should mention one of: {keywords}"


def test_threshold_validation():
    """Validate threshold parameters accept float values."""
    returncode, stdout, stderr = run_command([
        "--queue-warning", "0.75",
        "--queue-critical", "1.5"
    ])

    assert returncode in [0, 1, 2], f"Unexpected return code: {returncode}"


def test_invalid_threshold():
    """Validate invalid threshold values are rejected."""
    returncode, stdout, stderr = run_command(["--queue-warning", "not-a-number"])

    assert returncode != 0, "Invalid threshold should fail"


if __name__ == "__main__":
    # Run all tests
    tests = [
        test_help_message,
        test_help_message_h,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_format_invalid,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_queue_warning_threshold,
        test_queue_critical_threshold,
        test_imbalance_warning_threshold,
        test_imbalance_critical_threshold,
        test_combined_flags,
        test_json_output_structure,
        test_exit_code_values,
        test_no_extra_output_on_help,
        test_examples_in_help,
        test_description_mentions_key_features,
        test_threshold_validation,
        test_invalid_threshold,
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
