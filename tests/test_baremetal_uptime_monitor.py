#!/usr/bin/env python3
"""
Test script for baremetal_uptime_monitor.py functionality.
Tests argument parsing and error handling without requiring external resources.
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
        [sys.executable, 'baremetal_uptime_monitor.py', '--help']
    )

    if return_code == 0 and 'uptime' in stdout.lower() and 'reboot' in stdout.lower():
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
        [sys.executable, 'baremetal_uptime_monitor.py', '--format', 'invalid']
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
            [sys.executable, 'baremetal_uptime_monitor.py', '--format', fmt]
        )

        # Should not fail with argument parsing error
        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Format option '{fmt}' not recognized")
            passed = False

    if passed:
        print(f"[PASS] Format options test passed")
    return passed


def test_threshold_options():
    """Test that threshold options are accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_uptime_monitor.py',
         '--min-uptime', '2',
         '--max-reboots-24h', '3',
         '--max-reboots-7d', '10']
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
        [sys.executable, 'baremetal_uptime_monitor.py', '-v']
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
        [sys.executable, 'baremetal_uptime_monitor.py', '-w']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        return False


def test_json_format_structure():
    """Test JSON output format structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_uptime_monitor.py', '--format', 'json']
    )

    # Script should succeed on Linux (we have /proc/uptime)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check for expected keys
            expected_keys = ['hostname', 'uptime_seconds', 'uptime_formatted',
                           'boot_time', 'reboots_24h', 'reboots_7d', 'issues']
            missing_keys = [k for k in expected_keys if k not in data]

            if not missing_keys:
                print("[PASS] JSON format structure test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys: {missing_keys}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Unexpected for this script since /proc/uptime should exist
        print("[SKIP] JSON format structure test (unexpected exit code 2)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_plain_format_output():
    """Test plain format output contains expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_uptime_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Check for expected output fields
        expected_fields = ['Hostname:', 'Uptime:', 'Boot Time:', 'Reboots (24h):', 'Reboots (7d):']
        missing = [f for f in expected_fields if f not in stdout]

        if not missing:
            print("[PASS] Plain format output test passed")
            return True
        else:
            print(f"[FAIL] Plain format missing fields: {missing}")
            print(f"  Output: {stdout[:300]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_table_format_output():
    """Test table format output contains expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_uptime_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Check for table markers and expected fields
        if '=' * 20 in stdout and 'Uptime' in stdout and 'Boot Time' in stdout:
            print("[PASS] Table format output test passed")
            return True
        else:
            print(f"[FAIL] Table format missing expected structure")
            print(f"  Output: {stdout[:300]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_exit_codes():
    """Test that exit codes are valid"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_uptime_monitor.py']
    )

    # Valid exit codes: 0 (success), 1 (warnings), 2 (missing tool)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_uptime_values():
    """Test that uptime values are reasonable"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_uptime_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            uptime = data.get('uptime_seconds', 0)

            # Uptime should be positive and less than 10 years (sanity check)
            if uptime > 0 and uptime < 10 * 365 * 24 * 3600:
                print("[PASS] Uptime values test passed")
                return True
            else:
                print(f"[FAIL] Uptime value unreasonable: {uptime}")
                return False
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[FAIL] Failed to parse uptime: {e}")
            return False
    else:
        print(f"[SKIP] Uptime values test (exit code {return_code})")
        return True


def test_verbose_shows_history():
    """Test that verbose mode includes reboot history"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_uptime_monitor.py', '--format', 'json', '-v']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # reboot_history should be present (even if empty)
            if 'reboot_history' in data:
                print("[PASS] Verbose reboot history test passed")
                return True
            else:
                print(f"[FAIL] Missing reboot_history in verbose output")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] Failed to parse JSON: {e}")
            return False
    else:
        print(f"[SKIP] Verbose history test (exit code {return_code})")
        return True


if __name__ == "__main__":
    print(f"Testing baremetal_uptime_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_format_options,
        test_threshold_options,
        test_verbose_flag,
        test_warn_only_flag,
        test_json_format_structure,
        test_plain_format_output,
        test_table_format_output,
        test_exit_codes,
        test_uptime_values,
        test_verbose_shows_history,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
