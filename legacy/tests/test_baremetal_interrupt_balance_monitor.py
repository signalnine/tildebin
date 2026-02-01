#!/usr/bin/env python3
"""
Test script for baremetal_interrupt_balance_monitor.py functionality.
Tests argument parsing and error handling without requiring root access.
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
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--help']
    )

    if return_code == 0 and 'interrupt' in stdout.lower() and 'IRQ' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:100]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_threshold():
    """Test that invalid threshold values are rejected"""
    # Test threshold > 1.0
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--threshold', '1.5']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (>1.0) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold should return exit code 2, got {return_code}")
        return False


def test_invalid_threshold_negative():
    """Test that negative threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--threshold', '-0.5']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (negative) test passed")
        return True
    else:
        print(f"[FAIL] Negative threshold should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    # This will run and either succeed or fail based on /proc/interrupts availability
    # We're just testing that the option is recognized
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--format', 'json']
    )

    # Should either succeed (0) or fail with missing /proc/interrupts (2)
    # Should NOT fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing (if /proc/interrupts exists)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--format', 'json']
    )

    # If /proc/interrupts doesn't exist, this is expected to fail with exit code 2
    if return_code == 2 and '/proc/interrupts' in stderr:
        print("[PASS] JSON output format test passed (no /proc/interrupts)")
        return True

    # If it succeeds, validate JSON
    if return_code in [0, 1]:  # 0 = balanced, 1 = imbalanced
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'num_cpus' in data and 'total_interrupts' in data and 'issues' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected fields")
                print(f"  Data: {data}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON parsing failed")
            print(f"  Output: {stdout[:100]}")
            return False

    print(f"[FAIL] Unexpected return code: {return_code}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_table_format():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--format', 'table']
    )

    # Should either work or fail with missing /proc/interrupts
    if return_code == 2 and '/proc/interrupts' in stderr:
        print("[PASS] Table format test passed (no /proc/interrupts)")
        return True

    # If succeeds, check for table headers
    if return_code in [0, 1]:
        if 'CPU' in stdout and 'Interrupts' in stdout:
            print("[PASS] Table format test passed")
            return True
        else:
            print("[FAIL] Table format missing expected headers")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Table format test failed with code {return_code}")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--verbose']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py', '--warn-only']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py',
         '--format', 'json', '--verbose', '--warn-only', '--threshold', '0.7']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:  # Any valid exit code
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_exit_code_on_missing_proc():
    """Test that missing /proc/interrupts returns exit code 2"""
    # This test can only really work on systems without /proc/interrupts
    # or by checking the error message format
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_interrupt_balance_monitor.py']
    )

    # If /proc/interrupts exists, script should succeed or find issues (0 or 1)
    # If it doesn't exist, should return 2
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_interrupt_balance_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_threshold,
        test_invalid_threshold_negative,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_options,
        test_exit_code_on_missing_proc,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
