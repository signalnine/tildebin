#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_route_health_monitor.py functionality.
Tests argument parsing and error handling without requiring actual network access.
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
        [sys.executable, 'baremetal_route_health_monitor.py', '--help']
    )

    if return_code == 0 and 'routing health' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed - return code: {return_code}")
        print(f"  stdout: {stdout[:200]}")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '-v', '--no-ping']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_format_option():
    """Test that the format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--format', 'json', '--no-ping']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Format option test passed")
        return True
    else:
        print(f"[FAIL] Format option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_no_ping_option():
    """Test that the no-ping option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--no-ping']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] No-ping option test passed")
        return True
    else:
        print(f"[FAIL] No-ping option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--warn-only', '--no-ping']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_ping_count_option():
    """Test that the ping-count option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--ping-count', '5', '--no-ping']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Ping-count option test passed")
        return True
    else:
        print(f"[FAIL] Ping-count option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_ping_timeout_option():
    """Test that the ping-timeout option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--ping-timeout', '5', '--no-ping']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Ping-timeout option test passed")
        return True
    else:
        print(f"[FAIL] Ping-timeout option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_route_health_monitor.py',
        '-v',
        '--format', 'json',
        '--no-ping',
        '--warn-only'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_json_format_output():
    """Test that JSON format produces valid output structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--format', 'json', '--no-ping']
    )

    # Check if output is valid JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check for expected keys
            if 'default_routes' in data and 'healthy' in data:
                print("[PASS] JSON format output test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON format output test failed - invalid JSON: {e}")
            print(f"  stdout: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] JSON format output test failed with return code: {return_code}")
        return False


def test_json_structure():
    """Test that JSON output has all required fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--format', 'json', '--no-ping']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            required_keys = ['default_routes', 'gateway_status', 'interface_status', 'issues', 'warnings', 'healthy']
            missing_keys = [key for key in required_keys if key not in data]

            if not missing_keys:
                print("[PASS] JSON structure test passed")
                return True
            else:
                print(f"[FAIL] JSON structure test failed - missing keys: {missing_keys}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON structure test failed - invalid JSON")
            return False
    else:
        print(f"[FAIL] JSON structure test failed with return code: {return_code}")
        return False


def test_plain_output_contains_header():
    """Test that plain output contains expected header"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--no-ping']
    )

    if return_code in [0, 1] and 'Network Routing Health Monitor' in stdout:
        print("[PASS] Plain output header test passed")
        return True
    else:
        print("[FAIL] Plain output header test failed")
        print(f"  return code: {return_code}")
        print(f"  stdout: {stdout[:200]}")
        return False


def test_default_routes_section():
    """Test that plain output contains default routes section"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_route_health_monitor.py', '--no-ping']
    )

    if return_code in [0, 1] and 'Default Routes:' in stdout:
        print("[PASS] Default routes section test passed")
        return True
    else:
        print("[FAIL] Default routes section test failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_route_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_verbose_option,
        test_format_option,
        test_invalid_format,
        test_no_ping_option,
        test_warn_only_option,
        test_ping_count_option,
        test_ping_timeout_option,
        test_combined_options,
        test_json_format_output,
        test_json_structure,
        test_plain_output_contains_header,
        test_default_routes_section,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
