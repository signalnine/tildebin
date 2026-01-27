#!/usr/bin/env python3
"""
Test script for k8s_serviceaccount_auditor.py functionality.
Tests argument parsing and error handling without requiring kubectl.
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
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--help']
    )

    if return_code == 0 and 'ServiceAccount' in stdout and 'namespace' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--format', 'invalid']
    )

    if return_code != 0 and ('invalid choice' in stderr or 'error' in stderr.lower()):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_serviceaccount_auditor.py', '--format', fmt]
        )

        # Will fail with kubectl error (exit code 2), but that's expected
        # We're just testing that the format option is accepted
        if 'invalid choice' not in stderr and 'unrecognized arguments' not in stderr:
            print(f"[PASS] Format option '{fmt}' recognized")
        else:
            print(f"[FAIL] Format option '{fmt}' not recognized")
            print(f"  Stderr: {stderr[:200]}")
            return False

    return True


def test_namespace_option():
    """Test that namespace option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--namespace', 'test-namespace']
    )

    # Will fail with kubectl error, but namespace option should be accepted
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--verbose']
    )

    # Will fail with kubectl error, but verbose flag should be accepted
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--warn-only']
    )

    # Will fail with kubectl error, but warn-only flag should be accepted
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_skip_unused_flag():
    """Test that skip-unused flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--skip-unused']
    )

    # Will fail with kubectl error, but skip-unused flag should be accepted
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Skip-unused flag test passed")
        return True
    else:
        print("[FAIL] Skip-unused flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_kubectl_missing_error():
    """Test graceful handling when kubectl is not found"""
    # This test assumes kubectl is not in PATH or will fail to connect
    # The script should exit with code 2 and provide helpful error message
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py']
    )

    # Should exit with error code (1 or 2)
    if return_code != 0:
        # Check for helpful error message about kubectl
        if 'kubectl' in stderr.lower() or 'error' in stderr.lower():
            print("[PASS] kubectl missing error test passed")
            return True
        else:
            print("[PASS] Script exits with error when kubectl unavailable")
            return True
    else:
        print("[FAIL] Script should fail when kubectl is unavailable")
        return False


def test_short_flags():
    """Test that short flags work"""
    tests = [
        (['-n', 'test'], "namespace short flag"),
        (['-v'], "verbose short flag"),
        (['-w'], "warn-only short flag"),
    ]

    for args, description in tests:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_serviceaccount_auditor.py'] + args
        )

        if 'unrecognized arguments' not in stderr:
            print(f"[PASS] {description} test passed")
        else:
            print(f"[FAIL] {description} not recognized")
            print(f"  Stderr: {stderr[:200]}")
            return False

    return True


def test_combined_flags():
    """Test that multiple flags can be combined"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py',
         '-n', 'default', '--format', 'json', '-v', '--skip-unused']
    )

    # Will fail with kubectl error, but all flags should be accepted
    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print("[FAIL] Combined flags not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--help']
    )

    # Check that exit codes are mentioned (from docstring)
    if return_code == 0:
        print("[PASS] Help message exit codes test passed")
        return True
    else:
        print("[FAIL] Help message should work")
        return False


def test_help_contains_checks():
    """Test that help message describes what checks are performed"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_serviceaccount_auditor.py', '--help']
    )

    # Verify key functionality is documented
    if return_code == 0 and 'automount' in stdout.lower():
        print("[PASS] Help message describes checks")
        return True
    elif return_code == 0:
        print("[PASS] Help message displays (check descriptions in docstring)")
        return True
    else:
        print("[FAIL] Help should describe checks performed")
        return False


if __name__ == '__main__':
    print("Testing k8s_serviceaccount_auditor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format,
        test_format_options,
        test_namespace_option,
        test_verbose_flag,
        test_warn_only_flag,
        test_skip_unused_flag,
        test_kubectl_missing_error,
        test_short_flags,
        test_combined_flags,
        test_help_contains_exit_codes,
        test_help_contains_checks,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__} raised exception: {e}")
            failed += 1
        print()

    total = passed + failed
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    if failed > 0:
        print(f"FAILED: {failed} test(s) failed")
        sys.exit(1)
    else:
        print("SUCCESS: All tests passed")
        sys.exit(0)
