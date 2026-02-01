#!/usr/bin/env python3
"""
Test script for k8s_network_policy_audit.py functionality.
"""

import subprocess
import sys


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
        [sys.executable, 'k8s_network_policy_audit.py', '--help'])

    if return_code == 0 and 'Audit Kubernetes Network Policies' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_network_policy_audit.py', '--format', 'invalid'])

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print("[FAIL] Invalid format rejection test failed")
        return False


def test_format_options():
    """Test that format options are recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_network_policy_audit.py', '--help'])

    if return_code == 0 and 'plain' in stdout and 'json' in stdout and 'table' in stdout:
        print("[PASS] Format options test passed")
        return True
    else:
        print("[FAIL] Format options test failed")
        return False


def test_namespace_option():
    """Test that namespace option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_network_policy_audit.py', '--help'])

    if return_code == 0 and '--namespace' in stdout:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option test failed")
        return False


def test_warn_only_option():
    """Test that warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_network_policy_audit.py', '--help'])

    if return_code == 0 and '--warn-only' in stdout:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed")
        return False


def test_missing_kubectl_error():
    """Test graceful handling when kubectl is not available"""
    # Note: This test may pass or fail depending on whether kubectl is installed
    # We're mainly testing that the script doesn't crash
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_network_policy_audit.py'])

    # Script should either:
    # - Exit with code 2 and error message if kubectl missing
    # - Exit with code 0 or 1 if kubectl is available
    if return_code in [0, 1, 2]:
        print("[PASS] Script handles kubectl availability gracefully")
        return True
    else:
        print("[FAIL] Script crashed or returned unexpected code")
        return False


if __name__ == "__main__":
    print("Testing k8s_network_policy_audit.py...")

    tests = [
        test_help_message,
        test_invalid_format,
        test_format_options,
        test_namespace_option,
        test_warn_only_option,
        test_missing_kubectl_error,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
