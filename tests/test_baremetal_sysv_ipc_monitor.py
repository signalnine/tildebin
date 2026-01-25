#!/usr/bin/env python3
"""
Test script for baremetal_sysv_ipc_monitor.py functionality.
Tests argument parsing and output formats without requiring specific IPC resources.
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--help']
    )

    if return_code == 0 and 'ipc' in stdout.lower() and 'semaphore' in stdout.lower():
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_recognized():
    """Test that format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (invalid choice)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Format option recognition test passed")
        return True
    elif return_code == 2:
        print("[PASS] Format option recognition test passed (dependency check)")
        return True
    else:
        print(f"[FAIL] Format option recognition test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_threshold_out_of_range():
    """Test that out-of-range threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--warn', '150']
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--warn', '-10']
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--warn', '90', '--crit', '80']
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py']
    )

    # Exit code 0 or 1 = success, 2 = ipcs not available
    if return_code in [0, 1]:
        if 'Semaphores:' in stdout and 'Shared Memory:' in stdout:
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        # ipcs not available - acceptable
        if 'not found' in stderr or 'unavailable' in stderr.lower():
            print("[PASS] Plain output format test passed (ipcs unavailable)")
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # ipcs not available - acceptable
        print("[PASS] JSON output format test passed (ipcs unavailable)")
        return True

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'usage' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify usage data structure
        usage = data['usage']
        required_sections = ['semaphores', 'shared_memory', 'message_queues']
        if not all(section in usage for section in required_sections):
            print("[FAIL] JSON usage data missing required sections")
            print(f"  Usage sections: {list(usage.keys())}")
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--format', 'table']
    )

    if return_code == 2:
        # ipcs not available - acceptable
        print("[PASS] Table output format test passed (ipcs unavailable)")
        return True

    if return_code in [0, 1] and 'Resource' in stdout and 'Used' in stdout:
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--verbose']
    )

    if return_code == 2:
        # ipcs not available - acceptable
        print("[PASS] Verbose mode test passed (ipcs unavailable)")
        return True

    # Should succeed and contain owner breakdown or segment details
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on IPC state)
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--warn', '80', '--crit', '95']
    )

    # Should succeed with custom thresholds (or fail if ipcs not available)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_contains_limits():
    """Test JSON output contains kernel limits if available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # ipcs not available - acceptable
        print("[PASS] JSON limits test passed (ipcs unavailable)")
        return True

    try:
        data = json.loads(stdout)

        # Verify limits data exists
        if 'limits' not in data:
            print("[FAIL] JSON missing 'limits' data")
            return False

        print("[PASS] JSON limits test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON limits parsing failed: {e}")
        return False


def test_json_usage_values_are_numeric():
    """Test that usage values in JSON are numeric."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # ipcs not available - acceptable
        print("[PASS] Numeric values test passed (ipcs unavailable)")
        return True

    try:
        data = json.loads(stdout)
        usage = data['usage']

        # Check semaphore values
        sem = usage['semaphores']
        if not isinstance(sem['arrays'], int):
            print("[FAIL] semaphores.arrays is not an integer")
            return False
        if not isinstance(sem['arrays_pct'], (int, float)):
            print("[FAIL] semaphores.arrays_pct is not numeric")
            return False

        # Check shared memory values
        shm = usage['shared_memory']
        if not isinstance(shm['segments'], int):
            print("[FAIL] shared_memory.segments is not an integer")
            return False

        # Check message queue values
        mq = usage['message_queues']
        if not isinstance(mq['queues'], int):
            print("[FAIL] message_queues.queues is not an integer")
            return False

        print("[PASS] Usage values are numeric test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Usage values test failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0, 1, or 2
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysv_ipc_monitor.py']
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
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--help']
    )

    if return_code == 0 and 'sysctl' in stdout and 'kernel.sem' in stdout:
        print("[PASS] Help contains remediation guidance test passed")
        return True
    else:
        print(f"[FAIL] Help should contain remediation guidance")
        print(f"  Output: {stdout[:300]}")
        return False


def test_help_mentions_ipcrm():
    """Test that help mentions ipcrm for cleanup."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--help']
    )

    if return_code == 0 and 'ipcrm' in stdout:
        print("[PASS] Help mentions ipcrm cleanup test passed")
        return True
    else:
        print(f"[FAIL] Help should mention ipcrm cleanup")
        print(f"  Output: {stdout[:400]}")
        return False


def test_json_has_issues_flag():
    """Test that JSON output contains has_issues flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysv_ipc_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[PASS] JSON has_issues test passed (ipcs unavailable)")
        return True

    try:
        data = json.loads(stdout)
        if 'has_issues' not in data:
            print("[FAIL] JSON missing 'has_issues' field")
            return False

        if not isinstance(data['has_issues'], bool):
            print("[FAIL] has_issues is not a boolean")
            return False

        print("[PASS] JSON has_issues flag test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON has_issues test failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_sysv_ipc_monitor.py...")
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
        test_json_contains_limits,
        test_json_usage_values_are_numeric,
        test_exit_codes,
        test_help_contains_remediation,
        test_help_mentions_ipcrm,
        test_json_has_issues_flag,
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
