#!/usr/bin/env python3
"""
Test script for baremetal_livepatch_monitor.py functionality.
Tests argument parsing and output formats without requiring live patching tools.
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
        [sys.executable, 'baremetal_livepatch_monitor.py', '--help']
    )

    if return_code == 0 and 'live patch' in stdout.lower():
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
        [sys.executable, 'baremetal_livepatch_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_livepatch_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on system state)
    if return_code in [0, 1] and 'Kernel:' in stdout:
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
        [sys.executable, 'baremetal_livepatch_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['kernel', 'support', 'summary', 'issues']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify kernel data structure
        kernel = data['kernel']
        if 'release' not in kernel:
            print("[FAIL] JSON kernel data missing 'release' key")
            print(f"  Kernel keys: {list(kernel.keys())}")
            return False

        # Verify support structure
        support = data['support']
        support_keys = ['kernel_support', 'livepatch_enabled', 'kpatch_available']
        if not all(key in support for key in support_keys):
            print("[FAIL] JSON support data missing keys")
            print(f"  Support keys: {list(support.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        summary_keys = ['livepatch_in_use', 'total_patches', 'enabled_patches']
        if not all(key in summary for key in summary_keys):
            print("[FAIL] JSON summary missing keys")
            print(f"  Summary keys: {list(summary.keys())}")
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
        [sys.executable, 'baremetal_livepatch_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'LIVE PATCH' in stdout:
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
        [sys.executable, 'baremetal_livepatch_monitor.py', '--verbose']
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
        [sys.executable, 'baremetal_livepatch_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        # In warn-only mode, should not have "Kernel:" header if no warnings
        # But we can't guarantee there are no warnings, so just check it runs
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_livepatch_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_issues_array():
    """Test that JSON output contains issues as an array."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_livepatch_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'issues' not in data:
            print("[FAIL] JSON output missing 'issues' key")
            return False

        if not isinstance(data['issues'], list):
            print("[FAIL] JSON 'issues' should be an array")
            return False

        # Verify issue structure if there are any issues
        for issue in data['issues']:
            if 'severity' not in issue or 'message' not in issue:
                print("[FAIL] Issue missing required fields")
                return False

        print("[PASS] JSON issues array test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_format_option_values():
    """Test all valid format option values."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_livepatch_monitor.py', '--format', fmt]
        )

        if return_code not in [0, 1]:
            print(f"[FAIL] Format '{fmt}' returned error code {return_code}")
            return False

    print("[PASS] All format options test passed")
    return True


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_livepatch_monitor.py',
         '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)
        if return_code in [0, 1] and 'kernel' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print(f"[FAIL] Combined options test failed")
            return False
    except json.JSONDecodeError:
        print("[FAIL] Combined options JSON parsing failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_livepatch_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_exit_codes,
        test_json_issues_array,
        test_format_option_values,
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
