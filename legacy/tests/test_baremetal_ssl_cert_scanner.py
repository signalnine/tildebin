#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_ssl_cert_scanner.py functionality.
Tests argument parsing and error handling without requiring actual certificates.
"""

import subprocess
import sys
import os
import tempfile
import json


def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(cmd_args,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--help']
    )

    if return_code == 0 and 'SSL/TLS certificates' in stdout and 'expiration' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_path_option():
    """Test that the path option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '-p', '/nonexistent/path']
    )

    # Should succeed with no certs found (exit 0) or find certs elsewhere
    if return_code in [0, 1]:
        print("[PASS] Path option test passed")
        return True
    else:
        print("[FAIL] Path option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_multiple_paths():
    """Test that multiple path options can be specified"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_ssl_cert_scanner.py',
        '-p', '/nonexistent/path1',
        '-p', '/nonexistent/path2'
    ])

    if return_code in [0, 1]:
        print("[PASS] Multiple paths test passed")
        return True
    else:
        print("[FAIL] Multiple paths test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_days_option():
    """Test that the days option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--days', '60']
    )

    if return_code in [0, 1]:
        print("[PASS] Days option test passed")
        return True
    else:
        print("[FAIL] Days option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_days():
    """Test that invalid days value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--days', 'notanumber']
    )

    if return_code != 0:
        print("[PASS] Invalid days test passed")
        return True
    else:
        print("[FAIL] Invalid days test failed - should have rejected non-numeric days")
        return False


def test_format_option_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--format', 'json', '-p', '/nonexistent']
    )

    if return_code in [0, 1]:
        try:
            # Should produce valid JSON (empty array or list of certs)
            data = json.loads(stdout)
            if isinstance(data, list):
                print("[PASS] Format JSON option test passed")
                return True
            else:
                print("[FAIL] Format JSON option test failed - output is not a list")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Format JSON option test failed - invalid JSON output")
            print("stdout: " + stdout[:200])
            return False
    else:
        print("[FAIL] Format JSON option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        print("[PASS] Format table option test passed")
        return True
    else:
        print("[FAIL] Format table option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--format', 'invalid']
    )

    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '-v']
    )

    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '-w']
    )

    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_no_recursive_option():
    """Test that the no-recursive option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ssl_cert_scanner.py', '--no-recursive']
    )

    if return_code in [0, 1]:
        print("[PASS] No-recursive option test passed")
        return True
    else:
        print("[FAIL] No-recursive option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_ssl_cert_scanner.py',
        '-p', '/nonexistent',
        '-v',
        '-w',
        '--days', '60',
        '--format', 'plain'
    ])

    if return_code in [0, 1]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_empty_path_produces_empty_json():
    """Test that scanning empty/nonexistent path produces empty JSON array"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_ssl_cert_scanner.py',
        '-p', '/nonexistent/definitely/not/real',
        '--format', 'json'
    ])

    if return_code == 0:
        try:
            data = json.loads(stdout)
            if data == []:
                print("[PASS] Empty path produces empty JSON array test passed")
                return True
            else:
                print("[FAIL] Empty path test failed - expected empty array")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Empty path test failed - invalid JSON")
            return False
    else:
        print("[FAIL] Empty path test failed with return code: " + str(return_code))
        return False


def test_real_system_certs():
    """Test scanning real system certificate directory if it exists"""
    # Check if /etc/ssl/certs exists (common on most Linux systems)
    cert_path = '/etc/ssl/certs'
    if not os.path.exists(cert_path):
        print("[SKIP] Real system certs test skipped - /etc/ssl/certs not found")
        return True

    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_ssl_cert_scanner.py',
        '-p', cert_path,
        '--format', 'json'
    ])

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                print("[PASS] Real system certs test passed (found " + str(len(data)) + " certs)")
                return True
            else:
                print("[FAIL] Real system certs test failed - output is not a list")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Real system certs test failed - invalid JSON output")
            return False
    else:
        print("[FAIL] Real system certs test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


if __name__ == "__main__":
    print("Testing baremetal_ssl_cert_scanner.py...")

    tests = [
        test_help_message,
        test_path_option,
        test_multiple_paths,
        test_days_option,
        test_invalid_days,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_option,
        test_warn_only_option,
        test_no_recursive_option,
        test_combined_options,
        test_empty_path_produces_empty_json,
        test_real_system_certs,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\nTest Results: " + str(passed) + "/" + str(total) + " tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
