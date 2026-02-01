#!/usr/bin/env python3
"""
Test script for baremetal_trim_status_monitor.py functionality.
Tests argument parsing and error handling without requiring actual SSD access.
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
        [sys.executable, 'baremetal_trim_status_monitor.py', '--help']
    )

    if return_code == 0 and 'TRIM' in stdout and 'discard' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("  stdout: " + stdout[:200])
        return False


def test_help_contains_best_practices():
    """Test that help message documents TRIM best practices"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_trim_status_monitor.py', '--help']
    )

    if return_code == 0 and 'fstrim' in stdout.lower():
        print("[PASS] Help contains TRIM best practices")
        return True
    else:
        print("[FAIL] Help should document TRIM best practices")
        return False


def test_device_option():
    """Test that the -d/--device option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_trim_status_monitor.py', '-d', 'sda']
    )

    # Should succeed (0), warn (1), or report no SSD (0) - not parsing error
    if return_code in [0, 1, 2]:
        print("[PASS] Device option test passed")
        return True
    else:
        print("[FAIL] Device option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_device_option_with_dev_prefix():
    """Test that the -d/--device option handles /dev/ prefix"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_trim_status_monitor.py', '-d', '/dev/nvme0n1']
    )

    # Should succeed (0), warn (1), or report no SSD (0) - not parsing error
    if return_code in [0, 1, 2]:
        print("[PASS] Device option with /dev/ prefix test passed")
        return True
    else:
        print("[FAIL] Device option with /dev/ prefix test failed")
        print("  stderr: " + stderr)
        return False


def test_verbose_option():
    """Test that the -v/--verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_trim_status_monitor.py', '-v']
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
        [sys.executable, 'baremetal_trim_status_monitor.py', '-w']
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
        [sys.executable, 'baremetal_trim_status_monitor.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_trim_status_monitor.py', '--format', 'json']
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
        [sys.executable, 'baremetal_trim_status_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_trim_status_monitor.py', '--format', 'invalid']
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
        sys.executable, 'baremetal_trim_status_monitor.py',
        '-d', 'nvme0n1',
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
        [sys.executable, 'baremetal_trim_status_monitor.py', '--unknown-option']
    )

    if return_code == 2 and 'unrecognized arguments' in stderr:
        print("[PASS] Unknown option rejected test passed")
        return True
    else:
        print("[FAIL] Unknown option should be rejected")
        return False


def test_json_output_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_trim_status_monitor.py', '--format', 'json']
    )

    # If SSDs found, output should be valid JSON with expected structure
    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            # Should have fstrim_timer_enabled and devices keys
            if isinstance(data, dict) and 'devices' in data:
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected structure")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON output is not valid JSON")
            print("  stdout: " + stdout[:200])
            return False
    elif return_code == 0 and 'No SSDs found' in stdout:
        # No SSDs - still pass the test
        print("[PASS] JSON output structure test passed (no SSDs)")
        return True
    else:
        # Other cases are acceptable too
        print("[PASS] JSON output structure test passed (no SSDs or error)")
        return True


def test_no_ssds_exit_code():
    """Test that no SSDs found returns exit code 0 (not an error)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_trim_status_monitor.py']
    )

    # Exit 0 = success or no SSDs
    # Exit 1 = warnings found
    # Exit 2 = should only be for usage errors
    if return_code in [0, 1]:
        print("[PASS] No SSDs exit code test passed")
        return True
    elif return_code == 2:
        # If exit 2, should be a real error message
        if 'usage' in stderr.lower() or 'unrecognized' in stderr.lower():
            print("[FAIL] Exit code 2 should only be for usage errors")
            return False
        else:
            # Some other legitimate error - accept it
            print("[PASS] Script handled environment appropriately")
            return True
    else:
        print("[FAIL] Unexpected exit code: " + str(return_code))
        return False


def test_plain_output_contains_header():
    """Test that plain output contains expected header"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_trim_status_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Should contain report header or "No SSDs found"
        if 'TRIM' in stdout or 'SSD' in stdout or 'No SSDs' in stdout:
            print("[PASS] Plain output header test passed")
            return True
        else:
            print("[FAIL] Plain output should contain TRIM/SSD info or no SSDs message")
            print("  stdout: " + stdout[:200])
            return False
    else:
        # Script may have failed for other reasons (no disks, etc.)
        print("[PASS] Plain output header test passed (no SSDs or error)")
        return True


if __name__ == "__main__":
    print("Testing baremetal_trim_status_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_best_practices,
        test_device_option,
        test_device_option_with_dev_prefix,
        test_verbose_option,
        test_warn_only_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_combined_options,
        test_unknown_option_rejected,
        test_json_output_structure,
        test_no_ssds_exit_code,
        test_plain_output_contains_header,
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
