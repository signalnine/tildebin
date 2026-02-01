#!/usr/bin/env python3
"""
Test script for k8s_image_pull_analyzer.py functionality.
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
        [sys.executable, 'k8s_image_pull_analyzer.py', '--help']
    )

    if return_code == 0 and 'image pull' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option():
    """Test that format options are recognized"""
    # Test with --format json (will fail without kubectl, but option should parse)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '--format', 'json']
    )

    # Should fail with kubectl not found (exit code 2), not argument error
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Format option test passed (kubectl not found as expected)")
        return True
    # Or if kubectl exists, check for valid JSON output
    elif return_code in [0, 1]:
        try:
            json.loads(stdout)
            print("[PASS] Format option test passed (valid JSON output)")
            return True
        except json.JSONDecodeError:
            print("[FAIL] JSON format option produced invalid JSON")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Format option test failed with unexpected return code: {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '--format', 'xml']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_namespace_option():
    """Test that namespace option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '-n', 'test-namespace']
    )

    # Should fail with kubectl not found (exit code 2), not argument error
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Namespace option test passed")
        return True
    # Or succeed if kubectl exists
    elif return_code in [0, 1]:
        print("[PASS] Namespace option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Namespace option test failed with return code: {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False


def test_verbose_option():
    """Test that verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '-v']
    )

    # Should fail with kubectl not found (exit code 2), not argument error
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Verbose option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Verbose option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Verbose option test failed")
        return False


def test_warn_only_option():
    """Test that warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '--warn-only']
    )

    # Should fail with kubectl not found (exit code 2), not argument error
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Warn-only option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Warn-only option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed")
        return False


def test_max_age_option():
    """Test that max-age option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '--max-age', '30']
    )

    # Should fail with kubectl not found (exit code 2), not argument error
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Max-age option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Max-age option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Max-age option test failed")
        return False


def test_table_format():
    """Test table format output"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py', '--format', 'table']
    )

    # Should fail with kubectl not found (exit code 2), not argument error
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Table format test passed (kubectl not found as expected)")
        return True
    elif return_code in [0, 1]:
        # Check for table-like output
        if 'Type' in stdout or 'Count' in stdout or 'Image Pull Issues' in stdout:
            print("[PASS] Table format test passed")
            return True
        else:
            print("[FAIL] Table format did not produce expected output")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Table format test failed")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py',
         '-n', 'kube-system',
         '--format', 'json',
         '-v',
         '--warn-only',
         '--max-age', '120']
    )

    # Should fail with kubectl not found (exit code 2), not argument error
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Combined options test passed")
        return True
    elif return_code in [0, 1]:
        try:
            json.loads(stdout)
            print("[PASS] Combined options test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] Combined options produced invalid JSON")
            return False
    else:
        print(f"[FAIL] Combined options test failed")
        return False


def test_kubectl_not_found():
    """Test graceful handling when kubectl is not available"""
    # This test will pass if kubectl is not installed
    # or skip if kubectl is installed
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_image_pull_analyzer.py']
    )

    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] kubectl not found handling test passed")
        return True
    elif return_code in [0, 1]:
        # kubectl is installed, test passes
        print("[PASS] kubectl not found handling test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] kubectl not found handling test failed")
        print(f"  Return code: {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_image_pull_analyzer.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option,
        test_invalid_format,
        test_namespace_option,
        test_verbose_option,
        test_warn_only_option,
        test_max_age_option,
        test_table_format,
        test_combined_options,
        test_kubectl_not_found,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
