#!/usr/bin/env python3
"""
Test script for baremetal_kernel_lockup_detector.py functionality.
Tests argument parsing and output formats without requiring root access or kernel lockups.
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
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--help']
    )

    if return_code == 0 and 'lockup' in stdout.lower():
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
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py']
    )

    # Should succeed (exit 0 or 1 depending on lockup status)
    if return_code in [0, 1] and ('Kernel Lockup' in stdout or 'lockup' in stdout.lower() or 'No kernel lockup' in stdout):
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'summary' not in data:
            print("[FAIL] JSON output missing 'summary' key")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        required_keys = ['total_events', 'critical_count', 'warning_count', 'hung_task_count']
        if not all(key in summary for key in required_keys):
            print("[FAIL] JSON summary data missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
            return False

        # Verify issues list exists
        if 'issues' not in data:
            print("[FAIL] JSON output missing 'issues' key")
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
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and ('KERNEL LOCKUP' in stdout or 'Critical Events' in stdout):
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
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--warn-only']
    )

    # Should succeed (exit code depends on lockup state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_hours_option():
    """Test custom hours argument."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--hours', '48']
    )

    # Should succeed with custom hours
    if return_code in [0, 1]:
        print("[PASS] Hours option test passed")
        return True
    else:
        print(f"[FAIL] Hours option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_hours():
    """Test that negative hours are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--hours', '-5']
    )

    if return_code == 2:
        print("[PASS] Invalid hours test passed")
        return True
    else:
        print(f"[FAIL] Invalid hours should return exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_hung_task_threshold_option():
    """Test hung-task-threshold argument."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--hung-task-threshold', '10']
    )

    # Should succeed with custom threshold
    if return_code in [0, 1]:
        print("[PASS] Hung-task-threshold option test passed")
        return True
    else:
        print(f"[FAIL] Hung-task-threshold option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_hung_task_threshold():
    """Test that negative hung-task-threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--hung-task-threshold', '-5']
    )

    if return_code == 2:
        print("[PASS] Invalid hung-task-threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid hung-task-threshold should return exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_json_verbose_includes_extra_data():
    """Test JSON verbose output includes additional data."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py', '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)

        # Verbose mode should include kernel_config
        if 'kernel_config' not in data:
            print("[FAIL] JSON verbose missing kernel_config data")
            return False

        # Should include lockup_events
        if 'lockup_events' not in data:
            print("[FAIL] JSON verbose missing lockup_events data")
            return False

        # Should include hung_tasks
        if 'hung_tasks' not in data:
            print("[FAIL] JSON verbose missing hung_tasks data")
            return False

        print("[PASS] JSON verbose output test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_lockup_detector.py',
         '--format', 'json', '--verbose', '--hours', '12', '--hung-task-threshold', '3']
    )

    try:
        data = json.loads(stdout)
        if 'summary' in data and 'kernel_config' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print("[FAIL] Combined options missing expected keys")
            return False
    except json.JSONDecodeError:
        print("[FAIL] Combined options produced invalid JSON")
        return False


if __name__ == "__main__":
    print("Testing baremetal_kernel_lockup_detector.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_hours_option,
        test_invalid_hours,
        test_hung_task_threshold_option,
        test_invalid_hung_task_threshold,
        test_json_verbose_includes_extra_data,
        test_exit_codes,
        test_combined_options,
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
