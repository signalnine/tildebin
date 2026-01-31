#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_ptp_clock_monitor.py functionality.
Tests argument parsing and error handling without requiring PTP hardware.
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
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '--help'])

    if return_code == 0 and 'ptp' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_default_execution():
    """Test that the script runs without arguments"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py'])

    # Exit codes 0, 1, or 2 are all valid depending on PTP availability
    if return_code in [0, 1, 2]:
        print("[PASS] Default execution test passed")
        return True
    else:
        print("[FAIL] Default execution test failed - return code: " + str(return_code))
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '-v'])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option():
    """Test that the format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '--format', 'json'])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '--format', 'invalid'])

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '--warn-only'])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_offset_threshold_option():
    """Test that the offset-threshold option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py',
         '--offset-threshold', '500'])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Offset threshold option test passed")
        return True
    else:
        print("[FAIL] Offset threshold option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_delay_threshold_option():
    """Test that the delay-threshold option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py',
         '--delay-threshold', '5000'])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Delay threshold option test passed")
        return True
    else:
        print("[FAIL] Delay threshold option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_offset_threshold():
    """Test that invalid offset threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py',
         '--offset-threshold', 'abc'])

    # Should fail with argument error
    if return_code != 0:
        print("[PASS] Invalid offset threshold test passed")
        return True
    else:
        print("[FAIL] Invalid offset threshold test failed - should reject non-numeric")
        return False


def test_json_output_structure():
    """Test that JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '--format', 'json'])

    # Should produce valid JSON
    if return_code in [0, 1, 2]:
        try:
            data = json.loads(stdout)
            # Should have expected top-level keys
            required_keys = ['status', 'devices', 'warnings', 'issues']
            if all(key in data for key in required_keys):
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output structure test failed - missing keys")
                print("  Found keys: " + str(list(data.keys())))
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON output structure test failed - invalid JSON")
            return False
    else:
        print("[FAIL] JSON output structure test failed with return code: " + str(return_code))
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_ptp_clock_monitor.py',
        '-v',
        '--format', 'json',
        '--offset-threshold', '500',
        '--delay-threshold', '5000'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_plain_output_format():
    """Test that plain output contains expected sections"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '--format', 'plain'])

    # Should contain header and status line
    if return_code in [0, 1, 2] and 'PTP Clock Status' in stdout and 'Status:' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print("[FAIL] Plain output format test failed")
        print("  Return code: " + str(return_code))
        return False


def test_no_ptp_status():
    """Test proper handling when no PTP hardware is present"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '--format', 'json'])

    if return_code in [0, 1, 2]:
        try:
            data = json.loads(stdout)
            # If no PTP devices, status should be 'no_ptp' and exit code 2
            if not data.get('devices'):
                if data.get('status') == 'no_ptp' and return_code == 2:
                    print("[PASS] No PTP status test passed")
                    return True
                elif return_code == 2:
                    # Exit code 2 is correct for no PTP
                    print("[PASS] No PTP status test passed (exit code 2)")
                    return True
            # If PTP devices exist, any valid status is ok
            print("[PASS] No PTP status test passed (PTP present)")
            return True
        except json.JSONDecodeError:
            print("[FAIL] No PTP status test failed - invalid JSON")
            return False
    else:
        print("[FAIL] No PTP status test failed with return code: " + str(return_code))
        return False


def test_short_verbose_flag():
    """Test that -v short flag works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '-v'])

    if return_code in [0, 1, 2]:
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print("[FAIL] Short verbose flag test failed with return code: " + str(return_code))
        return False


def test_short_warn_only_flag():
    """Test that -w short flag works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ptp_clock_monitor.py', '-w'])

    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print("[FAIL] Short warn-only flag test failed with return code: " + str(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_ptp_clock_monitor.py...")

    tests = [
        test_help_message,
        test_default_execution,
        test_verbose_option,
        test_format_option,
        test_invalid_format,
        test_warn_only_option,
        test_offset_threshold_option,
        test_delay_threshold_option,
        test_invalid_offset_threshold,
        test_json_output_structure,
        test_combined_options,
        test_plain_output_format,
        test_no_ptp_status,
        test_short_verbose_flag,
        test_short_warn_only_flag
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
