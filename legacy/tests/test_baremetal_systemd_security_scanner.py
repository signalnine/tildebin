#!/usr/bin/env python3
"""
Test script for baremetal_systemd_security_scanner.py functionality.
Tests argument parsing and error handling without requiring root access.
"""

import json
import subprocess
import sys


def run_command(cmd_args):
    """Helper function to run a command and return result."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--help']
    )

    if return_code == 0 and 'systemd' in stdout and 'security' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: {}".format(return_code))
        print("stdout: {}".format(stdout[:200]))
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_plain():
    """Test that plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_json():
    """Test that JSON format option is recognized and produces valid JSON."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--format', 'json']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        # If we got output and systemd-analyze is available, verify it's valid JSON
        if stdout.strip() and return_code != 2:
            try:
                data = json.loads(stdout)
                if 'threshold' in data and 'services' in data:
                    print("[PASS] JSON format option test passed (valid JSON with expected fields)")
                    return True
                else:
                    print("[FAIL] JSON output missing expected fields")
                    return False
            except json.JSONDecodeError:
                print("[FAIL] JSON format test failed - invalid JSON output")
                print("Output: {}".format(stdout[:200]))
                return False
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_table():
    """Test that table format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--format', 'invalid']
    )

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        print("return_code: {}, stderr: {}".format(return_code, stderr))
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_threshold_option():
    """Test that the threshold option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--threshold', '5.0']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Threshold option test passed")
        return True
    else:
        print("[FAIL] Threshold option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_threshold_short_option():
    """Test that the short threshold option (-t) is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '-t', '7.5']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Threshold short option test passed")
        return True
    else:
        print("[FAIL] Threshold short option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_service_option():
    """Test that the service option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--service', 'sshd.service']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Service option test passed")
        return True
    else:
        print("[FAIL] Service option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_service_short_option():
    """Test that the short service option (-s) is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '-s', 'sshd.service']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Service short option test passed")
        return True
    else:
        print("[FAIL] Service short option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_systemd_security_scanner.py',
        '-v',
        '--format', 'json',
        '--threshold', '4.0',
        '--warn-only'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_exit_code_documentation():
    """Test that exit codes are documented in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--help']
    )

    if return_code == 0:
        # Check for exit code documentation
        if 'Exit codes' in stdout or 'exit code' in stdout.lower():
            print("[PASS] Exit code documentation test passed")
            return True
        else:
            print("[FAIL] Exit codes not documented in help")
            return False
    else:
        print("[FAIL] Could not check exit code documentation")
        return False


def test_security_ratings_documentation():
    """Test that security ratings are documented in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--help']
    )

    if return_code == 0:
        # Check for security rating documentation
        if 'OK' in stdout and 'EXPOSED' in stdout and 'UNSAFE' in stdout:
            print("[PASS] Security ratings documentation test passed")
            return True
        else:
            print("[FAIL] Security ratings not documented in help")
            return False
    else:
        print("[FAIL] Could not check security ratings documentation")
        return False


def test_json_output_structure():
    """Test that JSON output has the expected structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--format', 'json']
    )

    if return_code == 2:
        # systemd-analyze not available - skip this test
        print("[SKIP] JSON structure test - systemd-analyze not available")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            expected_keys = ['threshold', 'total_services', 'services_above_threshold', 'services']
            missing_keys = [k for k in expected_keys if k not in data]

            if not missing_keys:
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[FAIL] Unexpected return code: {}".format(return_code))
        return False


def test_invalid_threshold():
    """Test that invalid threshold value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_systemd_security_scanner.py', '--threshold', 'notanumber']
    )

    # Should fail with argument error
    if return_code != 0:
        print("[PASS] Invalid threshold test passed")
        return True
    else:
        print("[FAIL] Invalid threshold test failed - should have rejected invalid value")
        return False


def test_single_service_json():
    """Test JSON output for single service analysis."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_systemd_security_scanner.py',
        '--service', 'sshd.service',
        '--format', 'json'
    ])

    if return_code == 2:
        # systemd-analyze not available - skip this test
        print("[SKIP] Single service JSON test - systemd-analyze not available")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Single service output should have service, exposure, rating
            if 'service' in data and 'exposure' in data and 'rating' in data:
                print("[PASS] Single service JSON test passed")
                return True
            else:
                print("[FAIL] Single service JSON missing expected fields")
                print("Output: {}".format(stdout[:200]))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] Single service JSON parsing failed: {}".format(e))
            return False
    else:
        print("[FAIL] Single service JSON test unexpected return code: {}".format(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_systemd_security_scanner.py...")
    print()

    tests = [
        test_help_message,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_threshold_option,
        test_threshold_short_option,
        test_service_option,
        test_service_short_option,
        test_combined_options,
        test_exit_code_documentation,
        test_security_ratings_documentation,
        test_json_output_structure,
        test_invalid_threshold,
        test_single_service_json,
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
