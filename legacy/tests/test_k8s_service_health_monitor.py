#!/usr/bin/env python3
"""
Test script for k8s_service_health_monitor.py functionality.
Tests argument parsing and error handling without requiring kubectl access.
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
        [sys.executable, 'k8s_service_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Monitor Kubernetes Service health' in stdout:
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
        [sys.executable, 'k8s_service_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (exit code 2)
    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_valid_format_options():
    """Test that valid format options are accepted"""
    formats = ['plain', 'json', 'table']
    all_passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_service_health_monitor.py', '--format', fmt]
        )

        # Will fail without kubectl (exit code 2), but format option should parse
        # Exit code should not be related to argument parsing (would be usage error)
        if 'invalid choice' not in stderr.lower() and 'unrecognized arguments' not in stderr.lower():
            continue
        else:
            print(f"[FAIL] Format option '{fmt}' not recognized")
            all_passed = False

    if all_passed:
        print("[PASS] Valid format options test passed")
    return all_passed


def test_namespace_option():
    """Test that namespace option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_service_health_monitor.py', '-n', 'test-namespace']
    )

    # Will fail without kubectl, but namespace option should be accepted
    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr.lower():
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_service_health_monitor.py', '-v']
    )

    # Will fail without kubectl, but -v flag should be accepted
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_service_health_monitor.py', '-w']
    )

    # Will fail without kubectl, but -w flag should be accepted
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_service_health_monitor.py',
         '-n', 'production',
         '--format', 'json',
         '-v',
         '-w']
    )

    # Will fail without kubectl, but all options should be accepted
    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr.lower():
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options not accepted")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_kubectl_missing_error():
    """Test that missing kubectl produces appropriate error"""
    # This test will only work if kubectl is not available
    # If kubectl is available, we skip this test
    return_code, stdout, stderr = run_command(
        ['which', 'kubectl']
    )

    if return_code == 0:
        print("[SKIP] kubectl is available, skipping missing kubectl test")
        return True

    # kubectl is not available, test error handling
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_service_health_monitor.py']
    )

    # Should exit with code 2 (missing dependency)
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] kubectl missing error test passed")
        return True
    else:
        print(f"[FAIL] kubectl missing error test failed")
        print(f"  Return code: {return_code} (expected 2)")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_script_is_executable():
    """Test that script has executable permissions"""
    import os
    is_executable = os.access('k8s_service_health_monitor.py', os.X_OK)

    if is_executable:
        print("[PASS] Script is executable")
        return True
    else:
        print("[FAIL] Script is not executable")
        return False


def test_shebang_present():
    """Test that script has proper shebang"""
    try:
        with open('k8s_service_health_monitor.py', 'r') as f:
            first_line = f.readline().strip()

        if first_line == '#!/usr/bin/env python3':
            print("[PASS] Shebang test passed")
            return True
        else:
            print(f"[FAIL] Invalid shebang: {first_line}")
            return False
    except Exception as e:
        print(f"[FAIL] Could not read script: {e}")
        return False


if __name__ == "__main__":
    print("Testing k8s_service_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_valid_format_options,
        test_namespace_option,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_options,
        test_kubectl_missing_error,
        test_script_is_executable,
        test_shebang_present,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
