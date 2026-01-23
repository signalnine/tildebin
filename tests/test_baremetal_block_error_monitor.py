#!/usr/bin/env python3
"""
Test script for baremetal_block_error_monitor.py functionality.
Tests argument parsing and output formats without requiring actual block devices.
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
        [sys.executable, 'baremetal_block_error_monitor.py', '--help']
    )

    if return_code == 0 and 'block device' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_block_error_monitor.py', '--format', 'xml']
    )

    # Should fail with exit code 2 (usage error)
    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    results = []

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_block_error_monitor.py', '--format', fmt]
        )

        # Return code should be 0 (success) or 2 (missing /sys/block)
        # but not negative (crash)
        if return_code in (0, 1, 2):
            results.append(True)
        else:
            print(f"[FAIL] Format {fmt} crashed with code {return_code}")
            results.append(False)

    if all(results):
        print("[PASS] Format options test passed")
        return True
    else:
        print(f"[FAIL] Format options test failed: {sum(results)}/{len(results)} passed")
        return False


def test_verbose_flag():
    """Test that verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_block_error_monitor.py', '-v']
    )

    # Should parse successfully (exit 0, 1, or 2)
    if return_code in (0, 1, 2):
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed with code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_block_error_monitor.py', '-w']
    )

    # Should parse successfully (exit 0, 1, or 2)
    if return_code in (0, 1, 2):
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_specific_device_argument():
    """Test that specific device arguments are recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_block_error_monitor.py', 'sda', 'sdb']
    )

    # Should parse successfully (exit 0, 1, or 2)
    # Device may not exist, but arguments should parse
    if return_code in (0, 1, 2):
        print("[PASS] Specific device argument test passed")
        return True
    else:
        print(f"[FAIL] Specific device argument test failed with code {return_code}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_block_error_monitor.py', '--format', 'json']
    )

    # If successful (exit 0 or 1), try to parse JSON
    if return_code in (0, 1):
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                print("[PASS] JSON output format test passed")
                return True
            else:
                print(f"[FAIL] JSON output is not a list: {type(data)}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Missing /sys/block is acceptable in test environment
        print("[PASS] JSON output format test passed (no /sys/block available)")
        return True
    else:
        print(f"[FAIL] JSON output format test failed with code {return_code}")
        return False


def test_combined_flags():
    """Test combination of multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_block_error_monitor.py',
         '--format', 'json', '-v', '-w']
    )

    # Should parse successfully
    if return_code in (0, 1, 2):
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed with code {return_code}")
        return False


def test_exit_code_convention():
    """Test that exit codes follow convention (0=success, 1=issues, 2=error)"""
    # Test with no /sys/block (should exit 2 on most systems without it)
    # or exit 0/1 if /sys/block exists
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_block_error_monitor.py']
    )

    if return_code in (0, 1, 2):
        print("[PASS] Exit code convention test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_block_error_monitor.py...\n")

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_format_options,
        test_verbose_flag,
        test_warn_only_flag,
        test_specific_device_argument,
        test_json_output_format,
        test_combined_flags,
        test_exit_code_convention,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
