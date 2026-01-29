#!/usr/bin/env python3
"""
Test script for baremetal_usb_device_monitor.py functionality.
Tests argument parsing and error handling without requiring actual USB devices.
"""

import subprocess
import sys
import json
import os
import tempfile


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
        [sys.executable, 'baremetal_usb_device_monitor.py', '--help']
    )

    if return_code == 0 and 'USB' in stdout and 'security' in stdout.lower():
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
        [sys.executable, 'baremetal_usb_device_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_parsing():
    """Test that format options are recognized."""
    test_cases = [
        (['--format', 'json'], 'json format'),
        (['--format', 'table'], 'table format'),
        (['--format', 'plain'], 'plain format'),
    ]

    for args, desc in test_cases:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_usb_device_monitor.py'] + args
        )

        # Should succeed (exit 0 or 1) or fail with sysfs error (exit 2)
        if return_code in [0, 1]:
            continue  # Options parsed, command ran
        elif return_code == 2:
            # sysfs not available - but options were parsed
            continue
        else:
            print(f"[FAIL] Format option test failed for {desc}")
            print(f"  Return code: {return_code}")
            return False

    print("[PASS] Format option parsing test passed")
    return True


def test_invalid_format_option():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py', '--verbose']
    )

    # Should succeed or fail with sysfs error, but not with argument error
    if return_code in [0, 1, 2]:
        if 'unrecognized' not in stderr.lower():
            print("[PASS] Verbose flag test passed")
            return True

    print(f"[FAIL] Verbose flag test failed")
    return False


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        if 'unrecognized' not in stderr.lower():
            print("[PASS] Warn-only flag test passed")
            return True

    print(f"[FAIL] Warn-only flag test failed")
    return False


def test_no_flag_storage_option():
    """Test that --no-flag-storage option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py', '--no-flag-storage']
    )

    if return_code in [0, 1, 2]:
        if 'unrecognized' not in stderr.lower():
            print("[PASS] No-flag-storage option test passed")
            return True

    print(f"[FAIL] No-flag-storage option test failed")
    return False


def test_whitelist_option():
    """Test that --whitelist option is recognized."""
    # Create a temporary whitelist file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("# Test whitelist\n")
        f.write("046d:c52b  # Logitech\n")
        f.write("8087:0024\n")
        whitelist_path = f.name

    try:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_usb_device_monitor.py',
             '--whitelist', whitelist_path]
        )

        if return_code in [0, 1, 2]:
            if 'unrecognized' not in stderr.lower():
                print("[PASS] Whitelist option test passed")
                return True

        print(f"[FAIL] Whitelist option test failed")
        return False
    finally:
        os.unlink(whitelist_path)


def test_nonexistent_whitelist():
    """Test error handling for nonexistent whitelist file."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py',
         '--whitelist', '/nonexistent/whitelist.txt']
    )

    if return_code == 2 and 'whitelist' in stderr.lower():
        print("[PASS] Nonexistent whitelist test passed")
        return True
    else:
        print(f"[FAIL] Nonexistent whitelist should return error")
        print(f"  Return code: {return_code}")
        return False


def test_json_output_format():
    """Test JSON output format is valid JSON."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # sysfs not available - skip JSON validation
        print("[INFO] Sysfs not available, skipping JSON validation")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected keys
            if 'summary' in data and 'has_issues' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Unexpected return code: {return_code}")
    return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py',
         '--format', 'json',
         '--verbose',
         '--no-flag-storage']
    )

    if return_code in [0, 1, 2]:
        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                if 'devices' in data:  # verbose adds devices list
                    print("[PASS] Combined options test passed")
                    return True
            except json.JSONDecodeError:
                pass

        # Accept exit code 2 if sysfs not available
        if return_code == 2:
            print("[PASS] Combined options test passed (sysfs unavailable)")
            return True

    print(f"[FAIL] Combined options test failed")
    return False


def test_sysfs_missing_handling():
    """Test graceful handling when sysfs is not available."""
    # This test documents expected behavior when run in container/chroot
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_usb_device_monitor.py']
    )

    # Exit code 0 or 1 means it ran successfully
    # Exit code 2 means sysfs not available (expected in some environments)
    if return_code in [0, 1, 2]:
        if return_code == 2:
            if 'sysfs' in stderr.lower() or 'not found' in stderr.lower():
                print("[PASS] Sysfs missing handling test passed")
                return True
        else:
            print("[PASS] Sysfs missing handling test passed (sysfs available)")
            return True

    print(f"[FAIL] Unexpected behavior when sysfs unavailable")
    return False


if __name__ == "__main__":
    print(f"Testing baremetal_usb_device_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_parsing,
        test_invalid_format_option,
        test_verbose_flag,
        test_warn_only_flag,
        test_no_flag_storage_option,
        test_whitelist_option,
        test_nonexistent_whitelist,
        test_json_output_format,
        test_combined_options,
        test_sysfs_missing_handling,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"Failed: {total - passed} test(s)")
        sys.exit(1)
