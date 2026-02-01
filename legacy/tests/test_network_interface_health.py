#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for network_interface_health.py functionality.
Tests argument parsing and error handling without requiring actual network access.
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
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '--help'])

    if return_code == 0 and 'network interface health' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_interface_option():
    """Test that the interface option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '-i', 'eth0'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Interface option test passed")
        return True
    else:
        print("[FAIL] Interface option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '-v'])

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
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '--format', 'json'])

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
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '--format', 'invalid'])

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '--warn-only'])

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
        sys.executable, 'network_interface_health.py',
        '-i', 'eth0',
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


def test_long_interface_option():
    """Test that the --interface long option works"""
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '--interface', 'lo'])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Long interface option test passed")
        return True
    else:
        print("[FAIL] Long interface option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_json_format_output():
    """Test that JSON format produces valid output structure"""
    return_code, stdout, stderr = run_command([sys.executable, 'network_interface_health.py', '--format', 'json'])

    # Check if output starts with [ or { (valid JSON array or object)
    if return_code in [0, 1] and (stdout.strip().startswith('[') or stdout.strip().startswith('{')):
        print("[PASS] JSON format output test passed")
        return True
    else:
        print("[FAIL] JSON format output test failed - output is not valid JSON")
        return False


if __name__ == "__main__":
    print("Testing network_interface_health.py...")

    tests = [
        test_help_message,
        test_interface_option,
        test_verbose_option,
        test_format_option,
        test_invalid_format,
        test_warn_only_option,
        test_combined_options,
        test_long_interface_option,
        test_json_format_output
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
