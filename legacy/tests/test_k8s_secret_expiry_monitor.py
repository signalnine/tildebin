#!/usr/bin/env python3
"""
Test script for k8s_secret_expiry_monitor.py functionality.
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
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--help']
    )

    if return_code == 0 and 'Secret age' in stdout and 'TLS certificate' in stdout:
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
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_parsing():
    """Test that format options are recognized"""
    test_cases = [
        (['--format', 'json'], 'json format'),
        (['--format', 'table'], 'table format'),
        (['--format', 'plain'], 'plain format'),
    ]

    for args, desc in test_cases:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_secret_expiry_monitor.py'] + args
        )

        # Will fail without kubectl, but should recognize the option
        # Exit code 2 means kubectl missing, which is expected
        if return_code == 2 and 'kubectl not found' in stderr:
            continue  # This is fine, option was parsed
        elif return_code == 0:
            # If kubectl exists, command succeeded
            continue
        elif return_code == 1:
            # If kubectl exists and found issues
            continue
        else:
            print(f"[FAIL] Format option test failed for {desc}")
            print(f"  Return code: {return_code}")
            print(f"  Stderr: {stderr[:200]}")
            return False

    print("[PASS] Format option parsing test passed")
    return True


def test_namespace_option():
    """Test that namespace option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '-n', 'test-namespace']
    )

    # Exit code 2 means kubectl missing, which is expected in test environment
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Namespace option test passed")
        return True
    elif return_code in [0, 1]:
        # If kubectl exists, command succeeded or found issues
        print("[PASS] Namespace option test passed")
        return True
    else:
        print(f"[FAIL] Namespace option test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_warn_only_flag():
    """Test that --warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--warn-only']
    )

    # Exit code 2 means kubectl missing, which is expected
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    elif return_code in [0, 1]:
        # If kubectl exists, command succeeded
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_expiry_threshold_options():
    """Test --expiry-warn and --expiry-critical options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py',
         '--expiry-warn', '60',
         '--expiry-critical', '14']
    )

    # Exit code 2 means kubectl missing, which is expected
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Expiry threshold options test passed")
        return True
    elif return_code in [0, 1]:
        # If kubectl exists, command succeeded
        print("[PASS] Expiry threshold options test passed")
        return True
    else:
        print(f"[FAIL] Expiry threshold options test failed")
        print(f"  Return code: {return_code}")
        return False


def test_stale_days_option():
    """Test --stale-days option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--stale-days', '180']
    )

    # Exit code 2 means kubectl missing, which is expected
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Stale days option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Stale days option test passed")
        return True
    else:
        print(f"[FAIL] Stale days option test failed")
        return False


def test_tls_only_option():
    """Test --tls-only option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--tls-only']
    )

    # Exit code 2 means kubectl missing, which is expected
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] TLS-only option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] TLS-only option test passed")
        return True
    else:
        print(f"[FAIL] TLS-only option test failed")
        return False


def test_verbose_option():
    """Test --verbose option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '-v']
    )

    # Exit code 2 means kubectl missing, which is expected
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Verbose option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed")
        return False


def test_kubectl_missing_error():
    """Test graceful handling when kubectl is not available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py']
    )

    # If kubectl exists, this test is informational only
    if return_code == 0 or return_code == 1:
        print("[INFO] kubectl is available, skipping missing kubectl test")
        return True

    # Should get exit code 2 (dependency missing)
    if return_code == 2 and 'kubectl not found' in stderr:
        if 'Install kubectl' in stderr:
            print("[PASS] kubectl missing error handling test passed")
            return True
        else:
            print("[FAIL] Error message should include installation hint")
            return False
    else:
        print(f"[FAIL] kubectl missing should return exit code 2")
        print(f"  Got return code: {return_code}")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py',
         '-n', 'test-ns',
         '--format', 'json',
         '--warn-only',
         '--tls-only',
         '--expiry-warn', '45']
    )

    # Exit code 2 means kubectl missing, which is expected
    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Combined options test passed")
        return True
    elif return_code in [0, 1]:
        # If kubectl exists, test JSON parsing
        try:
            data = json.loads(stdout)
            if 'secrets' in data and 'summary' in data and 'timestamp' in data:
                print("[PASS] Combined options test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print(f"[FAIL] Combined options test failed")
        return False


def test_invalid_expiry_threshold():
    """Test that invalid (non-integer) expiry threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--expiry-warn', 'abc']
    )

    if return_code != 0 and 'invalid int' in stderr:
        print("[PASS] Invalid expiry threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid expiry threshold should be rejected")
        return False


def test_help_exit_codes_documented():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_secret_expiry_monitor.py', '--help']
    )

    if return_code == 0:
        if 'Exit codes:' in stdout and '0' in stdout and '1' in stdout and '2' in stdout:
            print("[PASS] Exit codes documentation test passed")
            return True
        else:
            print("[FAIL] Help should document exit codes")
            return False
    else:
        print(f"[FAIL] Help command failed")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_secret_expiry_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_parsing,
        test_namespace_option,
        test_warn_only_flag,
        test_expiry_threshold_options,
        test_stale_days_option,
        test_tls_only_option,
        test_verbose_option,
        test_kubectl_missing_error,
        test_invalid_format_option,
        test_combined_options,
        test_invalid_expiry_threshold,
        test_help_exit_codes_documented,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"Failed: {total - passed} test(s)")
        sys.exit(1)
