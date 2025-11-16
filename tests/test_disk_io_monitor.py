#!/usr/bin/env python3
"""
Test script for disk_io_monitor.py functionality.
Tests argument parsing and error handling without requiring iostat.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result"""
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
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--help']
    )

    if return_code == 0 and 'disk I/O performance' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:100]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--format', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should fail")
        return False


def test_format_option_plain():
    """Test plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--format', 'plain']
    )

    # Will exit with 2 if iostat missing, which is expected
    # We're just testing that the option is recognized
    if 'invalid choice' not in stderr.lower() and 'unrecognized arguments' not in stderr.lower():
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_format_option_json():
    """Test JSON format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--format', 'json']
    )

    # Will exit with 2 if iostat missing, which is expected
    # We're just testing that the option is recognized
    if 'invalid choice' not in stderr.lower() and 'unrecognized arguments' not in stderr.lower():
        print("[PASS] JSON format option test passed")
        return True
    else:
        print(f"[FAIL] JSON format option test failed")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_format_option_table():
    """Test table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--format', 'table']
    )

    # Will exit with 2 if iostat missing, which is expected
    # We're just testing that the option is recognized
    if 'invalid choice' not in stderr.lower() and 'unrecognized arguments' not in stderr.lower():
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--warn-only']
    )

    # Will exit with 2 if iostat missing, which is expected
    # We're just testing that the option is recognized
    if 'unrecognized arguments' not in stderr.lower():
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_verbose_flag():
    """Test verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--verbose']
    )

    # Will exit with 2 if iostat missing, which is expected
    # We're just testing that the option is recognized
    if 'unrecognized arguments' not in stderr.lower():
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_missing_iostat_handling():
    """Test graceful handling when iostat is missing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py']
    )

    # Should exit with code 2 (dependency missing) or run successfully
    # We test that it doesn't crash with code -1
    if return_code in [0, 1, 2]:
        print("[PASS] Missing iostat handling test passed")
        return True
    else:
        print(f"[FAIL] Missing iostat handling test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'disk_io_monitor.py', '--format', 'json', '--warn-only', '--verbose']
    )

    # Will exit with 2 if iostat missing, which is expected
    # We're just testing that the options are recognized
    if 'invalid choice' not in stderr.lower() and 'unrecognized arguments' not in stderr.lower():
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Stderr: {stderr[:100]}")
        return False


if __name__ == "__main__":
    print(f"Testing disk_io_monitor.py...")

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_format,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_warn_only_flag,
        test_verbose_flag,
        test_missing_iostat_handling,
        test_combined_options,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
