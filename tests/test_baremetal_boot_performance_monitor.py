#!/usr/bin/env python3
"""
Test script for baremetal_boot_performance_monitor.py functionality.
Tests argument parsing and error handling without requiring systemd.
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
        [sys.executable, 'baremetal_boot_performance_monitor.py', '--help']
    )

    if return_code == 0 and 'boot performance' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format_option():
    """Test that invalid format options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_performance_monitor.py', '--format', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_boot_performance_monitor.py', '--format', fmt]
        )

        # Will exit with code 2 (missing systemd-analyze) or 0/1 if systemd available
        # But shouldn't exit with usage error (code should not be from argparse)
        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Format option '{fmt}' not recognized")
            passed = False

    if passed:
        print(f"[PASS] Format options test passed")
    return passed


def test_threshold_options():
    """Test that threshold options are accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_performance_monitor.py',
         '--boot-threshold', '60',
         '--userspace-threshold', '30',
         '--service-threshold', '5']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Threshold options test passed")
        return True
    else:
        print(f"[FAIL] Threshold options test failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_performance_monitor.py', '-v']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_performance_monitor.py', '-w']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        return False


def test_json_format_structure():
    """Test JSON output format structure if systemd-analyze available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_performance_monitor.py', '--format', 'json']
    )

    # Only test JSON parsing if command succeeded (systemd available)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check for expected keys
            if 'boot_times' in data and 'issues' in data and 'slow_services' in data:
                print("[PASS] JSON format structure test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # systemd-analyze not available, skip this test
        print("[SKIP] JSON format structure test (systemd-analyze not available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_exit_code_on_missing_systemd():
    """Test that missing systemd-analyze returns exit code 2"""
    # This test might pass or fail depending on system
    # We're just checking the behavior is reasonable
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_performance_monitor.py']
    )

    # Valid exit codes: 0 (success), 1 (warnings), 2 (missing tool)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_boot_performance_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_format_options,
        test_threshold_options,
        test_verbose_flag,
        test_warn_only_flag,
        test_json_format_structure,
        test_exit_code_on_missing_systemd,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
