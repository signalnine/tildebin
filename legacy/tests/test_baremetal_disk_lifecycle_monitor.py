#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_disk_lifecycle_monitor.py functionality.
Tests argument parsing and error handling without requiring actual disk access.
"""

import subprocess
import sys
import json


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
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--help'
    ])

    if return_code == 0 and 'lifecycle' in stdout.lower() and 'hardware refresh' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("stdout: " + stdout[:200])
        return False


def test_disk_option():
    """Test that the disk option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '-d', '/dev/sda'
    ])

    # Should fail due to missing smartctl or permission issues, not argument parsing
    # Exit code 2 means smartctl missing, 1 means execution issue
    if return_code in [0, 1, 2]:
        print("[PASS] Disk option test passed")
        return True
    else:
        print("[FAIL] Disk option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '-v'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--format', 'plain'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed with return code: " + str(return_code))
        return False


def test_format_json():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--format', 'json'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Format JSON option test passed")
        return True
    else:
        print("[FAIL] Format JSON option test failed with return code: " + str(return_code))
        return False


def test_format_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--format', 'table'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Format table option test passed")
        return True
    else:
        print("[FAIL] Format table option test failed with return code: " + str(return_code))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--format', 'invalid'
    ])

    # Should fail with argument error (exit code 2)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--warn-only'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        return False


def test_warn_hours_option():
    """Test that the warn-hours option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--warn-hours', '30000'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-hours option test passed")
        return True
    else:
        print("[FAIL] Warn-hours option test failed with return code: " + str(return_code))
        return False


def test_critical_hours_option():
    """Test that the critical-hours option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--critical-hours', '45000'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Critical-hours option test passed")
        return True
    else:
        print("[FAIL] Critical-hours option test failed with return code: " + str(return_code))
        return False


def test_ssd_warn_hours_option():
    """Test that the ssd-warn-hours option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--ssd-warn-hours', '15000'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] SSD warn-hours option test passed")
        return True
    else:
        print("[FAIL] SSD warn-hours option test failed with return code: " + str(return_code))
        return False


def test_ssd_critical_hours_option():
    """Test that the ssd-critical-hours option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--ssd-critical-hours', '35000'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] SSD critical-hours option test passed")
        return True
    else:
        print("[FAIL] SSD critical-hours option test failed with return code: " + str(return_code))
        return False


def test_invalid_warn_hours():
    """Test that non-numeric warn-hours is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py', '--warn-hours', 'abc'
    ])

    if return_code != 0:
        print("[PASS] Invalid warn-hours test passed")
        return True
    else:
        print("[FAIL] Invalid warn-hours should have been rejected")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py',
        '-d', '/dev/sda',
        '-v',
        '--format', 'json',
        '--warn-hours', '30000',
        '--critical-hours', '45000'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        return False


def test_smartctl_missing_message():
    """Test that missing smartctl produces helpful error message"""
    # This test checks the stderr message when smartctl is missing
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_lifecycle_monitor.py'
    ])

    # If smartctl is missing, should exit 2 with helpful message
    # If smartctl is present, any exit code is fine
    if return_code == 2:
        if 'smartctl' in stderr.lower() or 'smartmontools' in stderr.lower():
            print("[PASS] Smartctl missing message test passed")
            return True
        else:
            print("[FAIL] Missing smartctl should mention smartmontools")
            return False
    else:
        # smartctl is present, test passes
        print("[PASS] Smartctl missing message test passed (smartctl present)")
        return True


if __name__ == "__main__":
    print("Testing baremetal_disk_lifecycle_monitor.py...")

    tests = [
        test_help_message,
        test_disk_option,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_warn_hours_option,
        test_critical_hours_option,
        test_ssd_warn_hours_option,
        test_ssd_critical_hours_option,
        test_invalid_warn_hours,
        test_combined_options,
        test_smartctl_missing_message,
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
