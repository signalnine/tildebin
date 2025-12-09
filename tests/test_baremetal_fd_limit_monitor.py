#!/usr/bin/env python3
"""
Test script for baremetal_fd_limit_monitor.py functionality.
Tests argument parsing, output formats, and error handling without requiring
specific system state.
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
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--help']
    )

    if return_code == 0 and 'file descriptor' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_basic_execution():
    """Test basic execution without arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Basic execution test passed")
        return True
    else:
        print(f"[FAIL] Basic execution test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format and parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON format test failed - wrong return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        # Check expected structure
        if 'system' in data and 'processes' in data:
            if isinstance(data['processes'], list):
                print("[PASS] JSON output format test passed")
                return True
            else:
                print(f"[FAIL] JSON processes field is not a list")
                return False
        else:
            print(f"[FAIL] JSON missing expected fields")
            print(f"  Keys found: {list(data.keys())}")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--format', 'table']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Check for table formatting characters
        if '─' in stdout or '│' in stdout or 'System' in stdout:
            print("[PASS] Table output format test passed")
            return True
        else:
            print(f"[FAIL] Table format missing expected formatting")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Table format test failed - wrong return code: {return_code}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--format', 'plain']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Should have system stats or process info
        if 'System FD Usage' in stdout or 'No processes' in stdout:
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain format missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Plain format test failed - wrong return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should return exit code 2, got {return_code}")
        return False


def test_threshold_option():
    """Test custom threshold option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--threshold', '90']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Threshold option test passed")
        return True
    else:
        print(f"[FAIL] Threshold option test failed - return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_threshold():
    """Test that invalid threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--threshold', '150']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2 and 'threshold' in stderr.lower():
        print("[PASS] Invalid threshold rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold should return exit code 2, got {return_code}")
        return False


def test_all_flag():
    """Test --all flag to show all processes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--all']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --all flag test passed")
        return True
    else:
        print(f"[FAIL] --all flag test failed - return code: {return_code}")
        return False


def test_verbose_flag():
    """Test verbose output flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--verbose']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed - return code: {return_code}")
        return False


def test_name_filter():
    """Test process name filtering."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--name', 'python']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Name filter test passed")
        return True
    else:
        print(f"[FAIL] Name filter test failed - return code: {return_code}")
        return False


def test_user_filter():
    """Test process user filtering."""
    # Use 'root' as a common user that likely exists
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--user', 'root']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] User filter test passed")
        return True
    else:
        print(f"[FAIL] User filter test failed - return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py',
         '--format', 'json', '--threshold', '50', '--verbose']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] Combined options test failed - return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        print("[PASS] Combined options test passed")
        return True
    except json.JSONDecodeError:
        print(f"[FAIL] Combined options produced invalid JSON")
        return False


def test_warn_only_flag():
    """Test --warn-only flag (should behave like default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fd_limit_monitor.py', '--warn-only']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] --warn-only flag test failed - return code: {return_code}")
        return False


if __name__ == '__main__':
    print("Testing baremetal_fd_limit_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_basic_execution,
        test_json_output_format,
        test_table_output_format,
        test_plain_output_format,
        test_invalid_format,
        test_threshold_option,
        test_invalid_threshold,
        test_all_flag,
        test_verbose_flag,
        test_name_filter,
        test_user_filter,
        test_combined_options,
        test_warn_only_flag,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)
