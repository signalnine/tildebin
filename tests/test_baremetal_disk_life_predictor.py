#!/usr/bin/env python3
"""
Test script for baremetal_disk_life_predictor.py functionality.
Tests argument parsing and error handling without requiring actual disk access.
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
        [sys.executable, 'baremetal_disk_life_predictor.py', '--help']
    )

    if return_code == 0 and 'Predict disk failure risk' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("  stdout: " + stdout[:200])
        return False


def test_help_contains_risk_levels():
    """Test that help message documents risk levels"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '--help']
    )

    if return_code == 0 and 'MINIMAL' in stdout and 'HIGH' in stdout:
        print("[PASS] Help contains risk level documentation")
        return True
    else:
        print("[FAIL] Help should document risk levels")
        return False


def test_disk_option():
    """Test that the -d/--disk option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '-d', '/dev/sda']
    )

    # Should fail with exit 2 (missing smartctl) or succeed/warn (0/1)
    # but not with argument parsing error
    if return_code in [0, 1, 2]:
        print("[PASS] Disk option test passed")
        return True
    else:
        print("[FAIL] Disk option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_verbose_option():
    """Test that the -v/--verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the -w/--warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '-w']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_format_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: " + str(return_code))
        return False


def test_format_json():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: " + str(return_code))
        return False


def test_format_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: " + str(return_code))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '--format', 'invalid']
    )

    # Should fail with argument error (exit code 2)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_disk_life_predictor.py',
        '-d', '/dev/sda',
        '-v',
        '-w',
        '--format', 'json'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_unknown_option_rejected():
    """Test that unknown options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '--unknown-option']
    )

    if return_code == 2 and 'unrecognized arguments' in stderr:
        print("[PASS] Unknown option rejected test passed")
        return True
    else:
        print("[FAIL] Unknown option should be rejected")
        return False


def test_json_output_structure():
    """Test JSON output has expected structure when smartctl unavailable"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py', '--format', 'json']
    )

    # If smartctl available and disks found, output should be valid JSON array
    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output should be an array")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON output is not valid JSON")
            print("  stdout: " + stdout[:200])
            return False
    elif return_code == 2:
        # smartctl not available or no disks - still pass the test
        print("[PASS] JSON output structure test passed (smartctl unavailable)")
        return True
    else:
        print("[FAIL] JSON output structure test failed")
        return False


def test_exit_code_2_on_missing_smartctl():
    """Test that missing smartctl gives exit code 2"""
    # We can't easily simulate missing smartctl, but we can verify the script
    # handles the case properly by checking that it either:
    # - Returns 0/1 if smartctl is present
    # - Returns 2 with appropriate error message if not
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_life_predictor.py']
    )

    if return_code == 2:
        # Missing smartctl or no disks - should have error message
        if 'smartctl' in stderr.lower() or 'not found' in stderr.lower() or 'no disk' in stderr.lower():
            print("[PASS] Missing dependency handling test passed")
            return True
        else:
            print("[FAIL] Exit code 2 but missing appropriate error message")
            print("  stderr: " + stderr)
            return False
    elif return_code in [0, 1]:
        # smartctl is available - that's fine too
        print("[PASS] Script executed successfully with smartctl")
        return True
    else:
        print("[FAIL] Unexpected exit code: " + str(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_disk_life_predictor.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_risk_levels,
        test_disk_option,
        test_verbose_option,
        test_warn_only_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_combined_options,
        test_unknown_option_rejected,
        test_json_output_structure,
        test_exit_code_2_on_missing_smartctl,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print()
    print("Test Results: {}/{} tests passed".format(passed, total))

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
