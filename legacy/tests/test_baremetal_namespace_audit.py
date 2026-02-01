#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_namespace_audit.py functionality.
Tests argument parsing and error handling without requiring root access.
"""

import subprocess
import sys
import json
import os


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
        [sys.executable, 'baremetal_namespace_audit.py', '--help']
    )

    if return_code == 0 and 'namespace' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_format_option_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--format', 'plain']
    )

    # Should succeed (0), have warnings (1), or fail due to /proc issues (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        try:
            data = json.loads(stdout)
            # Should be a dict with expected keys or error message
            if isinstance(data, dict):
                if 'audit_results' in data or 'error' in data:
                    print("[PASS] Format JSON option test passed")
                    return True
                else:
                    print("[FAIL] Format JSON option test failed - missing expected keys")
                    return False
            else:
                print("[FAIL] Format JSON option test failed - expected dict")
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] Format JSON option test failed - invalid JSON output")
            print("Error: " + str(e))
            print("stdout: " + stdout[:200])
            return False
    else:
        print("[FAIL] Format JSON option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_format_option_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        # Table output should have header or error message
        if 'Namespace' in stdout or 'Error' in stderr or 'error' in stdout:
            print("[PASS] Format table option test passed")
            return True
        else:
            print("[FAIL] Format table option test failed - unexpected output")
            print("stdout: " + stdout[:200])
            return False
    else:
        print("[FAIL] Format table option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--format', 'invalid']
    )

    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_verbose_flag():
    """Test that verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--verbose']
    )

    # Should run without crashing (exit code 0, 1, or 2)
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag test failed with return code: " + str(return_code))
        return False


def test_warn_only_flag():
    """Test that warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag test failed with return code: " + str(return_code))
        return False


def test_summary_flag():
    """Test that summary flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--summary']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Summary flag test passed")
        return True
    else:
        print("[FAIL] Summary flag test failed with return code: " + str(return_code))
        return False


def test_types_option_valid():
    """Test that types option with valid namespace types works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--types', 'pid,net,mnt']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Types option (valid) test passed")
        return True
    else:
        print("[FAIL] Types option test failed with return code: " + str(return_code))
        return False


def test_types_option_invalid():
    """Test that invalid namespace type is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--types', 'invalid_ns']
    )

    if return_code == 2:
        # Should exit with code 2 for invalid namespace type
        if 'Invalid namespace' in stderr or 'invalid_ns' in stderr:
            print("[PASS] Types option (invalid) test passed")
            return True
        else:
            print("[FAIL] Types option test failed - expected error message about invalid type")
            return False
    else:
        print("[FAIL] Types option test should have failed with exit code 2")
        return False


def test_combined_json_verbose():
    """Test JSON output with verbose flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--format', 'json', '--verbose']
    )

    if return_code in [0, 1, 2]:
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                print("[PASS] Combined JSON verbose test passed")
                return True
            else:
                print("[FAIL] Combined JSON verbose test failed")
                return False
        except json.JSONDecodeError:
            # Check for error in JSON
            if 'error' in stdout.lower():
                print("[PASS] Combined JSON verbose test passed (with error)")
                return True
            print("[FAIL] Combined JSON verbose test failed - invalid JSON")
            return False
    else:
        print("[FAIL] Combined JSON verbose test failed with return code: " + str(return_code))
        return False


def test_namespace_statistics_in_output():
    """Test that output contains namespace statistics"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Plain output should mention namespace types
        has_stats = any(ns in stdout.lower() for ns in ['pid', 'net', 'mnt', 'ipc'])
        if has_stats:
            print("[PASS] Namespace statistics in output test passed")
            return True
        else:
            print("[FAIL] Namespace statistics not found in output")
            print("stdout: " + stdout[:300])
            return False
    elif return_code == 2:
        # Expected if /proc is not accessible
        print("[PASS] Namespace statistics test passed (proc not accessible)")
        return True
    else:
        print("[FAIL] Namespace statistics test failed")
        return False


def test_json_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_namespace_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check for expected top-level keys
            if 'timestamp' in data and 'audit_results' in data:
                audit_results = data['audit_results']

                # Check for expected keys in audit_results
                expected_keys = ['init_namespaces', 'statistics', 'issues']
                has_expected = all(k in audit_results for k in expected_keys)

                if has_expected:
                    print("[PASS] JSON structure test passed")
                    return True
                else:
                    print("[FAIL] JSON structure test failed - missing expected keys")
                    print("Keys found: " + str(list(audit_results.keys())))
                    return False
            else:
                print("[FAIL] JSON structure test failed - missing top-level keys")
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON structure test failed - parse error: " + str(e))
            return False
    elif return_code == 2:
        # Check for proper error JSON
        try:
            data = json.loads(stdout)
            if 'error' in data:
                print("[PASS] JSON structure test passed (with error)")
                return True
        except json.JSONDecodeError:
            pass
        print("[PASS] JSON structure test passed (proc not accessible)")
        return True
    else:
        print("[FAIL] JSON structure test failed with return code: " + str(return_code))
        return False


if __name__ == "__main__":
    print("Testing baremetal_namespace_audit.py...")
    print()

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_summary_flag,
        test_types_option_valid,
        test_types_option_invalid,
        test_combined_json_verbose,
        test_namespace_statistics_in_output,
        test_json_structure,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
