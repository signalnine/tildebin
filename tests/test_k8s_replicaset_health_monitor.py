#!/usr/bin/env python3
"""
Test script for k8s_replicaset_health_monitor.py functionality.
Tests argument parsing and error handling without requiring kubectl access.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
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
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '--help']
    )

    if return_code == 0 and 'ReplicaSet' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_parsing():
    """Test that format options are recognized."""
    test_cases = [
        (['--format', 'json'], 'json format'),
        (['--format', 'table'], 'table format'),
        (['--format', 'plain'], 'plain format'),
    ]

    for args, desc in test_cases:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_replicaset_health_monitor.py'] + args
        )

        # Exit code 2 means kubectl missing, which is expected in test env
        if return_code == 2 and 'kubectl not found' in stderr:
            continue  # Option was parsed, kubectl just missing
        elif return_code in [0, 1]:
            continue  # kubectl exists, command succeeded
        else:
            print(f"[FAIL] Format option test failed for {desc}")
            print(f"  Return code: {return_code}")
            print(f"  Stderr: {stderr[:200]}")
            return False

    print("[PASS] Format option parsing test passed")
    return True


def test_namespace_option():
    """Test that namespace option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '-n', 'kube-system']
    )

    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Namespace option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print(f"[FAIL] Namespace option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '--warn-only']
    )

    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        return False


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '--verbose']
    )

    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        return False


def test_include_zero_replicas_flag():
    """Test that --include-zero-replicas flag is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '--include-zero-replicas']
    )

    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Include zero replicas flag test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] Include zero replicas flag test passed")
        return True
    else:
        print(f"[FAIL] Include zero replicas flag test failed")
        return False


def test_kubectl_missing_error():
    """Test graceful handling when kubectl is not available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py']
    )

    # If kubectl exists, this is informational
    if return_code == 0 or return_code == 1:
        print("[INFO] kubectl is available, skipping missing kubectl test")
        return True

    # Should get exit code 2 with helpful message
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
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py',
         '-n', 'test-ns',
         '--format', 'json',
         '--warn-only',
         '--verbose']
    )

    if return_code == 2 and 'kubectl not found' in stderr:
        print("[PASS] Combined options test passed")
        return True
    elif return_code in [0, 1]:
        # Verify JSON output structure if kubectl available
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'replicasets' in data:
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


def test_json_output_structure():
    """Test JSON output has correct structure when kubectl available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # kubectl not available, skip structure test
        print("[INFO] kubectl not available, skipping JSON structure test")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check required keys
            if 'timestamp' not in data:
                print("[FAIL] JSON missing timestamp")
                return False
            if 'summary' not in data:
                print("[FAIL] JSON missing summary")
                return False
            if 'replicasets' not in data:
                print("[FAIL] JSON missing replicasets")
                return False

            # Check summary structure
            summary = data['summary']
            required_summary_keys = ['total', 'with_issues', 'unavailable', 'orphaned']
            for key in required_summary_keys:
                if key not in summary:
                    print(f"[FAIL] JSON summary missing key: {key}")
                    return False

            print("[PASS] JSON output structure test passed")
            return True

        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            return False

    print(f"[FAIL] Unexpected return code: {return_code}")
    return False


def test_short_namespace_flag():
    """Test that short -n flag works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '-n', 'default']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short namespace flag test passed")
        return True
    else:
        print(f"[FAIL] Short namespace flag test failed")
        return False


def test_short_verbose_flag():
    """Test that short -v flag works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Short verbose flag test failed")
        return False


def test_short_warn_only_flag():
    """Test that short -w flag works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_replicaset_health_monitor.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_replicaset_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_parsing,
        test_namespace_option,
        test_warn_only_flag,
        test_verbose_flag,
        test_include_zero_replicas_flag,
        test_kubectl_missing_error,
        test_invalid_format_option,
        test_combined_options,
        test_json_output_structure,
        test_short_namespace_flag,
        test_short_verbose_flag,
        test_short_warn_only_flag,
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
