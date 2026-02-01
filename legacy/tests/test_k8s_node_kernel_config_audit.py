#!/usr/bin/env python3
"""
Test script for k8s_node_kernel_config_audit.py functionality.
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
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--help']
    )

    # Check for success and expected content
    if return_code == 0 and 'kernel' in stdout.lower() and 'node' in stdout.lower():
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
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--format', 'invalid']
    )

    # Should fail with usage error (exit code 2)
    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print(f"[FAIL] Invalid format option should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_options():
    """Test that all format options are recognized"""
    formats = ['plain', 'json', 'table']
    all_passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_node_kernel_config_audit.py', '--format', fmt]
        )

        # Will fail without kubectl, but should recognize the format option
        # Exit code 2 means kubectl not found (dependency missing)
        if return_code == 2 and 'kubectl' in stderr.lower():
            # This is expected - format was parsed, kubectl missing
            continue
        elif return_code in [0, 1]:
            # kubectl exists and worked - test passes
            continue
        else:
            print(f"[FAIL] Format option '{fmt}' not recognized properly")
            print(f"  Return code: {return_code}")
            print(f"  Stderr: {stderr[:200]}")
            all_passed = False
            break

    if all_passed:
        print("[PASS] Format options test passed")
        return True
    return False


def test_verbose_option():
    """Test that --verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py', '-v']
    )

    # Will fail without kubectl, but should recognize the option
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Verbose option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Verbose option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Verbose option not recognized")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_warn_only_option():
    """Test that --warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--warn-only']
    )

    # Will fail without kubectl, but should recognize the option
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Warn-only option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Warn-only option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Warn-only option not recognized")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_consistency_only_option():
    """Test that --consistency-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--consistency-only']
    )

    # Will fail without kubectl, but should recognize the option
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Consistency-only option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Consistency-only option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Consistency-only option not recognized")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_node_selector_option():
    """Test that --node-selector option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--node-selector', 'node-role.kubernetes.io/worker=']
    )

    # Will fail without kubectl, but should recognize the option
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Node-selector option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Node-selector option test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Node-selector option not recognized")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_kubectl_missing_error():
    """Test graceful handling when kubectl is not found"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py']
    )

    # Should exit with code 2 and helpful error message
    # (unless kubectl happens to be installed and works)
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Kubectl missing error test passed")
        return True
    elif return_code in [0, 1]:
        # kubectl exists and worked - test passes
        print("[PASS] Kubectl missing error test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Kubectl missing error not handled properly")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combination of multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py',
         '--format', 'json',
         '--warn-only',
         '-v']
    )

    # Should parse all options
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] Combined options test passed")
        return True
    elif return_code in [0, 1]:
        # kubectl works - test passes
        print("[PASS] Combined options test passed (kubectl available)")
        return True
    else:
        print(f"[FAIL] Combined options not handled properly")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test that script uses proper exit codes"""
    # Test with invalid argument (should be exit code 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--invalid-flag']
    )

    if return_code == 2:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Invalid arguments should return exit code 2")
        print(f"  Got return code: {return_code}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help examples test passed")
        return True
    else:
        print(f"[FAIL] Help message should contain examples")
        print(f"  Return code: {return_code}")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_kernel_config_audit.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help message should document exit codes")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_node_kernel_config_audit.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_format_options,
        test_verbose_option,
        test_warn_only_option,
        test_consistency_only_option,
        test_node_selector_option,
        test_kubectl_missing_error,
        test_combined_options,
        test_exit_codes,
        test_help_contains_examples,
        test_help_contains_exit_codes,
    ]

    passed = 0
    failed = 0

    for test in tests:
        if test():
            passed += 1
        else:
            failed += 1
        print()

    print("=" * 60)
    print(f"Test Results: {passed}/{len(tests)} tests passed")

    if failed > 0:
        print(f"FAILED: {failed} test(s) failed")
        sys.exit(1)
    else:
        print("SUCCESS: All tests passed")
        sys.exit(0)
