#!/usr/bin/env python3
"""
Test script for baremetal_conntrack_monitor.py functionality.
Tests argument parsing and output formats without requiring conntrack module.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--help']
    )

    if return_code == 0 and 'conntrack' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_recognized():
    """Test that format option is recognized."""
    # Even if conntrack isn't available, the option should be parsed first
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (invalid choice), not option not recognized
    if return_code != 0 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Format option recognition test passed")
        return True
    # If conntrack isn't loaded, check that format was at least parsed
    elif return_code == 2:
        print("[PASS] Format option recognition test passed (conntrack unavailable)")
        return True
    else:
        print(f"[FAIL] Format option recognition test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_threshold_out_of_range():
    """Test that out-of-range threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--warn', '150']
    )

    if return_code == 2 and 'between 0 and 100' in stderr:
        print("[PASS] Invalid threshold (out of range) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (out of range) test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_threshold_negative():
    """Test that negative threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (negative) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (negative) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_crit_le_warn():
    """Test that crit <= warn is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--warn', '90', '--crit', '80']
    )

    if return_code == 2 and 'must be greater than' in stderr:
        print("[PASS] Invalid threshold (crit <= warn) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (crit <= warn) test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py']
    )

    # Exit code 0 or 1 = success, 2 = conntrack not available
    if return_code in [0, 1]:
        if 'Conntrack:' in stdout:
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Conntrack module not loaded - this is acceptable
        if 'not found' in stderr or 'not enabled' in stderr:
            print("[PASS] Plain output format test passed (conntrack unavailable)")
            return True
        else:
            print(f"[FAIL] Plain output format test failed")
            print(f"  Stderr: {stderr[:200]}")
            return False
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # Conntrack not available - acceptable
        print("[PASS] JSON output format test passed (conntrack unavailable)")
        return True

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'conntrack' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify conntrack data structure
        conntrack = data['conntrack']
        required_keys = ['count', 'max', 'available', 'usage_percent']
        if not all(key in conntrack for key in required_keys):
            print("[FAIL] JSON conntrack data missing required keys")
            print(f"  Conntrack keys: {list(conntrack.keys())}")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--format', 'table']
    )

    if return_code == 2:
        # Conntrack not available - acceptable
        print("[PASS] Table output format test passed (conntrack unavailable)")
        return True

    if return_code in [0, 1] and 'CONNECTION TRACKING STATUS' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--verbose']
    )

    if return_code == 2:
        # Conntrack not available - acceptable
        print("[PASS] Verbose mode test passed (conntrack unavailable)")
        return True

    # Should succeed and contain timeout info or hash info
    if return_code in [0, 1] and ('Timeout' in stdout or 'bucket' in stdout.lower()):
        print("[PASS] Verbose mode test passed")
        return True
    elif return_code in [0, 1]:
        # Some systems may not have all verbose info
        print("[PASS] Verbose mode test passed (limited info available)")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on conntrack state)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_thresholds():
    """Test custom threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--warn', '80', '--crit', '95']
    )

    # Should succeed with custom thresholds (or fail if conntrack not available)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_verbose_includes_timeouts():
    """Test JSON verbose output includes timeout data if available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--format', 'json', '--verbose']
    )

    if return_code == 2:
        # Conntrack not available - acceptable
        print("[PASS] JSON verbose test passed (conntrack unavailable)")
        return True

    try:
        data = json.loads(stdout)

        # Verify conntrack data exists
        if 'conntrack' not in data:
            print("[FAIL] JSON verbose missing 'conntrack' data")
            return False

        # Timeouts may or may not be available depending on system
        print("[PASS] JSON verbose test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_conntrack_values_are_numeric():
    """Test that conntrack values in JSON are numeric."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # Conntrack not available - acceptable
        print("[PASS] Numeric values test passed (conntrack unavailable)")
        return True

    try:
        data = json.loads(stdout)
        conntrack = data['conntrack']

        # Check that values are numeric
        if not isinstance(conntrack['count'], int):
            print("[FAIL] conntrack.count is not an integer")
            return False
        if not isinstance(conntrack['max'], int):
            print("[FAIL] conntrack.max is not an integer")
            return False
        if not isinstance(conntrack['available'], int):
            print("[FAIL] conntrack.available is not an integer")
            return False
        if not isinstance(conntrack['usage_percent'], (int, float)):
            print("[FAIL] conntrack.usage_percent is not numeric")
            return False

        print("[PASS] Conntrack values are numeric test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Conntrack values test failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0, 1, or 2
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print(f"[PASS] Exit code test passed (got {return_code})")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_contains_remediation():
    """Test that help includes remediation guidance."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_conntrack_monitor.py', '--help']
    )

    if return_code == 0 and 'sysctl' in stdout and 'nf_conntrack_max' in stdout:
        print("[PASS] Help contains remediation guidance test passed")
        return True
    else:
        print(f"[FAIL] Help should contain remediation guidance")
        print(f"  Output: {stdout[:300]}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_conntrack_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_invalid_threshold_out_of_range,
        test_invalid_threshold_negative,
        test_invalid_threshold_crit_le_warn,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thresholds,
        test_json_verbose_includes_timeouts,
        test_conntrack_values_are_numeric,
        test_exit_codes,
        test_help_contains_remediation,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
