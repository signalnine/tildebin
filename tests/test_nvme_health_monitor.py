#!/usr/bin/env python3
"""
Test script for nvme_health_monitor.py functionality.
Tests argument parsing and error handling without requiring nvme-cli.
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
        [sys.executable, 'nvme_health_monitor.py', '--help']
    )

    if return_code == 0 and 'NVMe SSD health' in stdout and 'wear level' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'nvme_health_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    all_passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'nvme_health_monitor.py', '--format', fmt]
        )

        # Should either succeed (exit 0) or fail with missing nvme-cli (exit 2)
        # Exit code 1 would indicate argument parsing error
        if return_code in [0, 2]:
            print(f"[PASS] Format option '{fmt}' recognized")
        else:
            print(f"[FAIL] Format option '{fmt}' not recognized properly")
            print(f"  Return code: {return_code}")
            print(f"  Stderr: {stderr[:100]}")
            all_passed = False

    return all_passed


def test_threshold_options():
    """Test threshold configuration options"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'nvme_health_monitor.py',
        '--warn-wear', '75',
        '--critical-wear', '85',
        '--warn-temp', '65',
        '--critical-temp', '75',
        '--max-unsafe-shutdowns', '5'
    ])

    # Should either succeed (exit 0) or fail with missing nvme-cli (exit 2)
    if return_code in [0, 2]:
        print("[PASS] Threshold options test passed")
        return True
    else:
        print(f"[FAIL] Threshold options test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'nvme_health_monitor.py', '-w']
    )

    # Should either succeed (exit 0) or fail with missing nvme-cli (exit 2)
    if return_code in [0, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'nvme_health_monitor.py', '-v']
    )

    # Should either succeed (exit 0) or fail with missing nvme-cli (exit 2)
    if return_code in [0, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_missing_nvme_cli_handling():
    """Test that missing nvme-cli is handled gracefully"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'nvme_health_monitor.py']
    )

    # Should exit with code 2 if nvme-cli is missing, or 0/1 if it's installed
    if return_code == 2 and 'nvme' in stderr and 'not found' in stderr:
        print("[PASS] Missing nvme-cli handled gracefully")
        return True
    elif return_code in [0, 1]:
        # nvme-cli is actually installed on this system
        print("[PASS] nvme-cli available, script executed")
        return True
    else:
        print(f"[FAIL] Unexpected error handling")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combination of multiple options"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'nvme_health_monitor.py',
        '--format', 'json',
        '--warn-only',
        '--warn-wear', '80'
    ])

    # Should either succeed (exit 0) or fail with missing nvme-cli (exit 2)
    if return_code in [0, 1, 2]:
        # If JSON format, try to parse output
        if return_code in [0, 1] and stdout:
            try:
                data = json.loads(stdout)
                print("[PASS] Combined options test passed (valid JSON)")
                return True
            except json.JSONDecodeError:
                # May not output JSON if no devices found
                if 'No NVMe devices' in stderr:
                    print("[PASS] Combined options test passed (no devices)")
                    return True
                print("[FAIL] JSON parsing failed")
                print(f"  Output: {stdout[:100]}")
                return False
        else:
            print("[PASS] Combined options test passed")
            return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing nvme_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_format,
        test_format_options,
        test_threshold_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_missing_nvme_cli_handling,
        test_combined_options
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
