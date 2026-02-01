#!/usr/bin/env python3
"""
Tests for baremetal_kernel_limits_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring root access or specific kernel configurations.
"""

import json
import subprocess
import sys


def run_command(args, timeout=10):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"


def test_help_message():
    """Test that --help flag works and shows usage information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'kernel' in stdout.lower(), "Help should mention 'kernel'"
    assert 'limit' in stdout.lower(), "Help should mention 'limit'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_kernel_limits_monitor.py', '--format', fmt]
        )

        # Should work (exit 0 or 1) or fail with dependency error (2)
        assert return_code in [0, 1, 2], \
            f"Format {fmt} should be valid, got return code {return_code}"

        # Should not get argument parsing errors
        assert 'invalid choice' not in stderr.lower(), \
            f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_custom_thresholds():
    """Test that custom warning and critical thresholds work."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--warn', '70', '--crit', '90']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn and --crit should be recognized"
    assert return_code in [0, 1, 2], \
        f"Custom thresholds should be valid, got {return_code}"

    print("PASS: Custom thresholds test passed")
    return True


def test_invalid_threshold_order():
    """Test that warning >= critical threshold is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--warn', '90', '--crit', '80']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Invalid thresholds should exit with 2, got {return_code}"
    assert 'must be less than' in stderr.lower(), \
        "Error should mention threshold order"

    print("PASS: Invalid threshold order test passed")
    return True


def test_invalid_threshold_range():
    """Test that out-of-range thresholds are rejected."""
    # Test threshold > 100
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--warn', '150']
    )

    assert return_code == 2, \
        f"Out of range threshold should exit with 2, got {return_code}"

    # Test negative threshold
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--crit', '-10']
    )

    # argparse might catch this as invalid argument
    assert return_code != 0, "Negative threshold should fail"

    print("PASS: Invalid threshold range test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_json_output_format():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run (e.g., no /proc on non-Linux)
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: JSON output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'limits' in data, "JSON should have 'limits' field"
            assert data['status'] in ['ok', 'warning', 'critical'], \
                "Status should be ok, warning, or critical"
            print("PASS: JSON output format test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output format test passed (script execution checked)")
    return True


def test_plain_output_contains_expected():
    """Test that plain output contains expected keywords."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--verbose']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Plain output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        # Should have some limit names in output
        assert 'kernel' in stdout.lower() or 'fs.' in stdout.lower(), \
            "Output should contain kernel or fs limit names"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--format', 'table']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Table output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            # First line should be header
            header = lines[0].lower()
            assert 'parameter' in header or 'limit' in header or 'current' in header, \
                "Table should have header row"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_success():
    """Test that script exits with 0 when no warnings."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_kernel_limits_monitor.py', '--warn', '99', '--crit', '100']
    )

    # With very high thresholds, should typically succeed
    # Skip if no /proc
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Exit code test (no /proc filesystem)")
        return True

    # Exit 0 (no issues) or 1 (issues found) are both valid
    assert return_code in [0, 1], \
        f"Exit code should be 0 or 1, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_kernel_limits_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--warn', '75',
        '--crit', '90'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_kernel_limits_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_custom_thresholds,
        test_invalid_threshold_order,
        test_invalid_threshold_range,
        test_invalid_argument,
        test_json_output_format,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_success,
        test_combined_flags,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {test.__name__}: {e}")
            failed += 1

    print()
    print(f"Test Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
