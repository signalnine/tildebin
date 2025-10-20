#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for disk_health_check.py functionality.
Tests argument parsing and error handling without requiring actual disk access.
"""

import subprocess
import sys


def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(cmd_args,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command([sys.executable, 'disk_health_check.py', '--help'])

    if return_code == 0 and 'Check disk health' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_disk_option():
    """Test that the disk option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'disk_health_check.py', '-d', '/dev/sda'])

    # Should fail due to missing smartctl or permission issues, not argument parsing
    if return_code in [0, 1]:
        print("[PASS] Disk option test passed")
        return True
    else:
        print("[FAIL] Disk option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'disk_health_check.py', '-v'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option():
    """Test that the format option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'disk_health_check.py', '--format', 'json'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([sys.executable, 'disk_health_check.py', '--format', 'invalid'])

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'disk_health_check.py', '--warn-only'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'disk_health_check.py',
        '-d', '/dev/sda',
        '-v',
        '--format', 'json'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


if __name__ == "__main__":
    print("Testing disk_health_check.py...")

    tests = [
        test_help_message,
        test_disk_option,
        test_verbose_option,
        test_format_option,
        test_invalid_format,
        test_warn_only_option,
        test_combined_options
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\nTest Results: " + str(passed) + "/" + str(total) + " tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
