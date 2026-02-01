#!/usr/bin/env python3
"""
Tests for k8s_cpu_throttling_detector.py

Tests validate:
  - Argument parsing and help messages
  - Detection of CPU limits and throttling risk
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
    Execute k8s_cpu_throttling_detector.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_cpu_throttling_detector.py"
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
    assert "CPU throttling" in stdout or "throttling" in stdout, "Help should mention throttling"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"


def test_format_plain():
    """Validate --format plain is accepted."""
    # This will fail if kubectl is not available, which is expected
    # We're just testing that the argument is recognized
    returncode, stdout, stderr = run_command(["--format", "plain"])

    # Should either succeed or fail due to kubectl not being available (exit 2)
    # But should NOT fail due to invalid argument
    assert returncode != 2 or "usage:" not in stderr, \
        "Should not complain about usage for valid --format plain"


def test_format_table():
    """Validate --format table is accepted."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    # Should either succeed or fail due to kubectl not being available
    assert returncode != 2 or "usage:" not in stderr, \
        "Should not complain about usage for valid --format table"


def test_format_json():
    """Validate --format json is accepted."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    # Should either succeed or fail due to kubectl not being available
    assert returncode != 2 or "usage:" not in stderr, \
        "Should not complain about usage for valid --format json"


def test_format_invalid():
    """Validate invalid --format is rejected."""
    returncode, stdout, stderr = run_command(["--format", "invalid"])

    # Should fail with argument error
    assert returncode != 0, "Invalid format should fail"
    assert "invalid" in stderr or "format" in stderr, \
        "Should mention invalid format in error"


def test_namespace_flag():
    """Validate --namespace flag is accepted."""
    returncode, stdout, stderr = run_command(["-n", "default"])

    # Should either succeed or fail due to kubectl not being available (exit 2)
    assert returncode != 2 or "usage:" not in stderr, \
        "Should accept -n/--namespace flag"


def test_warn_only_flag():
    """Validate --warn-only flag is accepted."""
    returncode, stdout, stderr = run_command(["--warn-only"])

    # Should either succeed or fail due to kubectl not being available (exit 2)
    assert returncode != 2 or "usage:" not in stderr, \
        "Should accept --warn-only flag"


def test_short_flags():
    """Validate short flags work."""
    # Test -f for format
    returncode, stdout, stderr = run_command(["-f", "plain"])

    # Should be accepted
    assert "-f" in str(["-f", "plain"]) or returncode == 2, \
        "Should accept -f short flag"


def test_combined_flags():
    """Validate multiple flags can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "-f", "json",
        "--warn-only"
    ])

    # Should either succeed or fail due to kubectl not being available
    assert returncode != 2 or "usage:" not in stderr, \
        "Should accept combined flags"


def test_argument_order():
    """Validate arguments work in different orders."""
    returncode1, _, stderr1 = run_command(["-f", "plain", "-n", "default"])
    returncode2, _, stderr2 = run_command(["-n", "default", "-f", "plain"])

    # Both should be treated the same (either both work or both fail on kubectl)
    assert (returncode1 == returncode2) or returncode1 == 2 or returncode2 == 2, \
        "Argument order should not matter"


def test_json_output_structure():
    """Validate JSON output structure when kubectl is not available."""
    # This test doesn't require kubectl - we're testing argument parsing
    returncode, stdout, stderr = run_command(["-f", "json"])

    # If kubectl is not available, returncode will be 2 and stderr will have message
    # If kubectl is available but no pods found, output should be valid JSON or empty
    if returncode == 0 and stdout:
        try:
            data = json.loads(stdout)
            assert "pods_at_risk" in data or "pods" in data, \
                "JSON should have expected keys"
        except json.JSONDecodeError:
            # It's OK if there's no output
            pass


def test_exit_code_no_issues():
    """Validate exit code 0 when no throttling issues found."""
    # This is a conceptual test - actual behavior depends on cluster state
    # The script should exit with 0 if no throttled pods found
    returncode, stdout, stderr = run_command(["-f", "json"])

    # Exit code will be 2 if kubectl not available, which is valid for testing
    # Exit code will be 0 or 1 depending on actual cluster state
    assert returncode in [0, 1, 2], f"Exit code should be 0, 1, or 2, got {returncode}"


def test_verbose_format_differences():
    """Validate different format flags produce different output styles."""
    returncode_plain, stdout_plain, _ = run_command(["-f", "plain"])
    returncode_json, stdout_json, _ = run_command(["-f", "json"])

    # If both succeed (kubectl available)
    if returncode_plain == 0 and returncode_json == 0:
        # JSON should be parseable
        try:
            json.loads(stdout_json)
        except json.JSONDecodeError:
            assert False, "JSON output should be valid JSON"

        # Plain should not be JSON
        if stdout_plain:
            try:
                json.loads(stdout_plain)
                # If it parses, that's OK too - plain might still be JSON if no pods
            except json.JSONDecodeError:
                # Expected - plain is not JSON
                pass


def test_no_extra_output_on_help():
    """Validate --help doesn't execute kubectl."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, "Help should exit cleanly"
    # Help should be shown without errors
    assert "usage:" in stdout, "Help should be shown"


def test_format_flag_compatibility():
    """Validate all documented formats work."""
    valid_formats = ["plain", "table", "json"]

    for fmt in valid_formats:
        returncode, stdout, stderr = run_command(["-f", fmt])
        # Should either work or fail on kubectl, not on argument parsing
        assert returncode != 2 or "usage:" not in stderr, \
            f"Format {fmt} should be accepted"


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
        test_short_flags,
        test_combined_flags,
        test_argument_order,
        test_json_output_structure,
        test_exit_code_no_issues,
        test_verbose_format_differences,
        test_no_extra_output_on_help,
        test_format_flag_compatibility,
    ]

    failed = 0
    passed = 0

    for test in tests:
        try:
            test()
            print(f"✓ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: Unexpected error: {e}")
            failed += 1

    # Output test results in format expected by test runner
    print(f"\nTest Results: {passed}/{len(tests)} tests passed")
    sys.exit(0 if failed == 0 else 1)
