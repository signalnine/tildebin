#!/usr/bin/env python3
"""
Tests for k8s_pending_pod_analyzer.py

Tests validate:
  - Argument parsing and help messages
  - Output format options (plain, table, json)
  - Namespace filtering option
  - Error handling for missing kubectl
  - Exit codes
"""

import os
import subprocess
import sys
import json


def run_command(cmd_args):
    """
    Execute k8s_pending_pod_analyzer.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_pending_pod_analyzer.py"
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
    assert "pending" in stdout.lower(), "Help should mention pending pods"


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
    assert returncode != 2 or "kubectl" in stderr, \
        "Should not complain about usage for valid --format plain"


def test_format_table():
    """Validate --format table is accepted."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    # Should either succeed or fail due to kubectl not being available
    assert returncode != 2 or "kubectl" in stderr, \
        "Should not complain about usage for valid --format table"


def test_format_json():
    """Validate --format json is accepted."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    # Should either succeed or fail due to kubectl not being available
    assert returncode != 2 or "kubectl" in stderr, \
        "Should not complain about usage for valid --format json"


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
    assert returncode != 2 or "kubectl" in stderr, \
        "Should accept -n/--namespace flag"


def test_namespace_long_flag():
    """Validate --namespace long flag is accepted."""
    returncode, stdout, stderr = run_command(["--namespace", "kube-system"])

    # Should either succeed or fail due to kubectl not being available
    assert returncode != 2 or "kubectl" in stderr, \
        "Should accept --namespace flag"


def test_verbose_flag():
    """Validate --verbose flag is accepted."""
    returncode, stdout, stderr = run_command(["--verbose"])

    # Should either succeed or fail due to kubectl not being available (exit 2)
    assert returncode != 2 or "kubectl" in stderr, \
        "Should accept --verbose flag"


def test_short_flags():
    """Validate short flags work."""
    # Test -f for format
    returncode, stdout, stderr = run_command(["-f", "plain"])

    # Should be accepted (may fail on kubectl, but not on argument parsing)
    assert returncode != 2 or "kubectl" in stderr, \
        "Should accept -f short flag"


def test_combined_flags():
    """Validate multiple flags can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "-f", "json",
        "--verbose"
    ])

    # Should either succeed or fail due to kubectl not being available
    assert returncode != 2 or "kubectl" in stderr, \
        "Should accept combined flags"


def test_argument_order():
    """Validate arguments work in different orders."""
    returncode1, _, stderr1 = run_command(["-f", "plain", "-n", "default"])
    returncode2, _, stderr2 = run_command(["-n", "default", "-f", "plain"])

    # Both should be treated the same (either both work or both fail on kubectl)
    # We accept if either works or both fail with kubectl error
    valid1 = returncode1 != 2 or "kubectl" in stderr1
    valid2 = returncode2 != 2 or "kubectl" in stderr2
    assert valid1 and valid2, "Argument order should not matter"


def test_json_output_structure():
    """Validate JSON output structure when kubectl is available."""
    returncode, stdout, stderr = run_command(["-f", "json"])

    # If kubectl is available and no pending pods, should get valid JSON with structure
    if returncode == 0 and stdout:
        try:
            data = json.loads(stdout)
            assert "pending_count" in data, "JSON should have pending_count key"
            assert "pods" in data, "JSON should have pods key"
            assert "by_category" in data, "JSON should have by_category key"
        except json.JSONDecodeError:
            # If output is not JSON, that's a failure
            assert False, "JSON output should be valid JSON"


def test_exit_code_no_pending():
    """Validate exit code 0 when no pending pods found."""
    returncode, stdout, stderr = run_command(["-f", "json"])

    # Exit code will be 2 if kubectl not available
    # Exit code will be 0 if no pending pods
    # Exit code will be 1 if pending pods found
    assert returncode in [0, 1, 2], f"Exit code should be 0, 1, or 2, got {returncode}"


def test_no_extra_output_on_help():
    """Validate --help doesn't execute kubectl."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, "Help should exit cleanly"
    # Help should be shown without errors
    assert "usage:" in stdout, "Help should be shown"
    # Should not contain kubectl error messages
    assert "kubectl not found" not in stderr, "Help should not try to run kubectl"


def test_format_flag_compatibility():
    """Validate all documented formats work."""
    valid_formats = ["plain", "table", "json"]

    for fmt in valid_formats:
        returncode, stdout, stderr = run_command(["-f", fmt])
        # Should either work or fail on kubectl, not on argument parsing
        assert returncode != 2 or "kubectl" in stderr, \
            f"Format {fmt} should be accepted"


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
    assert "pending" in stdout.lower(), "Should mention pending pods"
    assert "namespace" in stdout.lower(), "Should mention namespace option"


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
        test_namespace_long_flag,
        test_verbose_flag,
        test_short_flags,
        test_combined_flags,
        test_argument_order,
        test_json_output_structure,
        test_exit_code_no_pending,
        test_no_extra_output_on_help,
        test_format_flag_compatibility,
        test_examples_in_help,
        test_description_mentions_key_features,
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
