#!/usr/bin/env python3
"""
Test script for power_consumption_monitor.py functionality.
Tests argument parsing and error handling without requiring IPMI/turbostat/RAPL.
"""

import subprocess
import sys
import json


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
        [sys.executable, 'power_consumption_monitor.py', '--help']
    )

    if return_code == 0 and 'power consumption' in stdout.lower():
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
        [sys.executable, 'power_consumption_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_options():
    """Test that format options are recognized."""
    # Test each format option
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'power_consumption_monitor.py', '--format', fmt]
        )

        # Script will exit with 2 (no sensors) but should recognize the format option
        # If format option is invalid, argparse would exit with 2 and show usage
        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Format option '{fmt}' not recognized")
            return False

    print("[PASS] Format options test passed")
    return True


def test_skip_options():
    """Test that skip options are recognized."""
    skip_options = ['--skip-ipmi', '--skip-turbostat', '--skip-rapl']

    for opt in skip_options:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'power_consumption_monitor.py', opt]
        )

        # Should recognize the option (even if no sensors found)
        if 'unrecognized arguments' in stderr.lower():
            print(f"[FAIL] Skip option '{opt}' not recognized")
            print(f"  stderr: {stderr[:200]}")
            return False

    print("[PASS] Skip options test passed")
    return True


def test_verbose_option():
    """Test that verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'power_consumption_monitor.py', '-v']
    )

    # Should recognize the option
    if 'unrecognized arguments' in stderr.lower() and '-v' in stderr:
        print("[FAIL] Verbose option not recognized")
        print(f"  stderr: {stderr[:200]}")
        return False

    print("[PASS] Verbose option test passed")
    return True


def test_warn_only_option():
    """Test that warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'power_consumption_monitor.py', '-w']
    )

    # Should recognize the option
    if 'unrecognized arguments' in stderr.lower() and '-w' in stderr:
        print("[FAIL] Warn-only option not recognized")
        print(f"  stderr: {stderr[:200]}")
        return False

    print("[PASS] Warn-only option test passed")
    return True


def test_json_output_structure():
    """Test JSON output format structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'power_consumption_monitor.py', '--format', 'json']
    )

    # If sensors are available, output should be valid JSON
    if return_code == 0 or return_code == 1:
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                # Check structure of first item if available
                if len(data) > 0:
                    item = data[0]
                    required_keys = ['source', 'sensor', 'value', 'unit', 'status']
                    for key in required_keys:
                        if key not in item:
                            print(f"[FAIL] JSON output missing key: {key}")
                            return False
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output should be a list")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False

    # If no sensors found (exit code 2), that's acceptable for this test
    if return_code == 2:
        print("[PASS] JSON output structure test passed (no sensors available)")
        return True

    print(f"[FAIL] Unexpected return code: {return_code}")
    return False


def test_no_sensors_error():
    """Test graceful handling when no sensors are available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'power_consumption_monitor.py',
         '--skip-ipmi', '--skip-turbostat', '--skip-rapl']
    )

    # Should exit with code 2 and provide helpful error message
    if return_code == 2 and 'No power sensors found' in stderr:
        print("[PASS] No sensors error handling test passed")
        return True
    else:
        print(f"[FAIL] No sensors error handling test failed")
        print(f"  Return code: {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combination of multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'power_consumption_monitor.py',
         '--format', 'json', '-v', '-w']
    )

    # Should recognize all options
    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Combined options test failed")
        print(f"  stderr: {stderr[:200]}")
        return False

    print("[PASS] Combined options test passed")
    return True


if __name__ == "__main__":
    print("Testing power_consumption_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_options,
        test_skip_options,
        test_verbose_option,
        test_warn_only_option,
        test_json_output_structure,
        test_no_sensors_error,
        test_combined_options,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
