#!/usr/bin/env python3
"""
Test script for k8s_storageclass_health_monitor.py functionality.
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
        [sys.executable, 'k8s_storageclass_health_monitor.py', '--help']
    )

    if return_code == 0 and 'StorageClass' in stdout and 'CSI driver' in stdout:
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
        [sys.executable, 'k8s_storageclass_health_monitor.py', '--format', 'xml']
    )

    # Should fail with usage error (exit code 2 from argparse)
    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_storageclass_health_monitor.py', '--format', fmt]
        )

        # Will likely exit with code 2 (kubectl not found) but format should parse
        # We're just testing that the argument is accepted
        if 'invalid choice' not in stderr:
            print(f"[PASS] Format option '{fmt}' recognized")
        else:
            print(f"[FAIL] Format option '{fmt}' not recognized")
            return False

    return True


def test_namespace_option():
    """Test that namespace option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_storageclass_health_monitor.py', '-n', 'kube-system']
    )

    # Should fail due to kubectl not available, not due to bad arguments
    # Check that there's no "unrecognized arguments" error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print(f"[FAIL] Namespace option not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_storageclass_health_monitor.py', '--warn-only']
    )

    # Should fail due to kubectl not available, not due to bad arguments
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_storageclass_health_monitor.py', '-v']
    )

    # Should fail due to kubectl not available, not due to bad arguments
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_kubectl_not_found_handling():
    """Test graceful handling when kubectl is not available"""
    # Most systems won't have kubectl, so this should trigger the error handling
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_storageclass_health_monitor.py']
    )

    # Should exit with code 2 (dependency missing) and show helpful error
    if return_code == 2:
        if 'kubectl not found' in stderr or 'kubectl' in stderr.lower():
            print("[PASS] kubectl not found handling test passed")
            return True
        else:
            print(f"[FAIL] kubectl error message not helpful")
            print(f"  Stderr: {stderr[:200]}")
            return False
    else:
        # If kubectl is actually installed, we can't test this
        print("[SKIP] kubectl not found test (kubectl appears to be installed)")
        return True


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_storageclass_health_monitor.py',
         '-n', 'default',
         '--format', 'json',
         '--warn-only']
    )

    # Should parse all options without "unrecognized arguments" error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_short_flags():
    """Test short flag variants"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_storageclass_health_monitor.py', '-n', 'test', '-w', '-v']
    )

    # Should parse short flags without error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short flags test passed")
        return True
    else:
        print(f"[FAIL] Short flags not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_exit_code_consistency():
    """Test that exit codes follow the convention"""
    # Test with no kubectl (should be exit code 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_storageclass_health_monitor.py']
    )

    # Exit code should be 2 (kubectl not found) or 0 (if kubectl exists and cluster is healthy)
    # or 1 (if kubectl exists and issues found)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code consistency test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        print(f"  Expected: 0, 1, or 2")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_storageclass_health_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format,
        test_format_options,
        test_namespace_option,
        test_warn_only_flag,
        test_verbose_flag,
        test_kubectl_not_found_handling,
        test_combined_options,
        test_short_flags,
        test_exit_code_consistency,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print(f"✗ {total - passed} test(s) failed")
        sys.exit(1)
