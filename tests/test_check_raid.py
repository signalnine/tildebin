#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for check_raid.py functionality.
Tests argument parsing and error handling without requiring actual RAID arrays.
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
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--help'])

    if return_code == 0 and 'Check status' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_type_option_all():
    """Test that the type option accepts 'all'"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'all'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Type option 'all' test passed")
        return True
    else:
        print("[FAIL] Type option 'all' test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_type_option_software():
    """Test that the type option accepts 'software'"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'software'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Type option 'software' test passed")
        return True
    else:
        print("[FAIL] Type option 'software' test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_type_option_hardware():
    """Test that the type option accepts 'hardware'"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'hardware'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Type option 'hardware' test passed")
        return True
    else:
        print("[FAIL] Type option 'hardware' test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_type():
    """Test that invalid type option is rejected"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'invalid'])

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid type test passed")
        return True
    else:
        print("[FAIL] Invalid type test failed - should have rejected invalid type")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '-v'])

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
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--format', 'json'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--warn-only'])

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
        sys.executable, 'check_raid.py',
        '--type', 'software',
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
    print("Testing check_raid.py...")

    tests = [
        test_help_message,
        test_type_option_all,
        test_type_option_software,
        test_type_option_hardware,
        test_invalid_type,
        test_verbose_option,
        test_format_option,
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
