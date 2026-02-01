#!/usr/bin/env python3
"""
Tests for k8s_limitrange_auditor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import os


def run_command(cmd_args):
    """Run the k8s_limitrange_auditor.py script with given arguments."""
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = [sys.executable, os.path.join(script_dir, 'k8s_limitrange_auditor.py')] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=script_dir
    )
    return result.returncode, result.stdout, result.stderr


def test_help_message():
    """Test that --help flag works and shows usage information."""
    returncode, stdout, stderr = run_command(['--help'])

    if returncode != 0:
        print(f"[FAIL] Help message test: Expected return code 0, got {returncode}")
        return False

    if 'LimitRange' not in stdout:
        print("[FAIL] Help message test: 'LimitRange' not found in help output")
        return False

    if '--format' not in stdout:
        print("[FAIL] Help message test: --format option not found")
        return False

    if '--warn-only' not in stdout:
        print("[FAIL] Help message test: --warn-only option not found")
        return False

    if '--namespace' not in stdout:
        print("[FAIL] Help message test: --namespace option not found")
        return False

    if 'Examples:' not in stdout:
        print("[FAIL] Help message test: Examples section not found")
        return False

    print("[PASS] Help message test")
    return True


def test_help_message_short():
    """Test that -h flag works."""
    returncode, stdout, stderr = run_command(['-h'])

    if returncode != 0:
        print(f"[FAIL] Help message short test: Expected return code 0, got {returncode}")
        return False

    if 'LimitRange' not in stdout:
        print("[FAIL] Help message short test: 'LimitRange' not found")
        return False

    print("[PASS] Help message short test")
    return True


def test_format_option_plain():
    """Test --format plain option is accepted."""
    returncode, stdout, stderr = run_command(['--format', 'plain'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Format plain test: Unexpected return code {returncode}")
        return False

    if 'invalid choice' in stderr.lower():
        print("[FAIL] Format plain test: Option not recognized")
        return False

    print("[PASS] Format plain test")
    return True


def test_format_option_json():
    """Test --format json option is accepted."""
    returncode, stdout, stderr = run_command(['--format', 'json'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Format json test: Unexpected return code {returncode}")
        return False

    if 'invalid choice' in stderr.lower():
        print("[FAIL] Format json test: Option not recognized")
        return False

    print("[PASS] Format json test")
    return True


def test_format_option_table():
    """Test --format table option is accepted."""
    returncode, stdout, stderr = run_command(['--format', 'table'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Format table test: Unexpected return code {returncode}")
        return False

    if 'invalid choice' in stderr.lower():
        print("[FAIL] Format table test: Option not recognized")
        return False

    print("[PASS] Format table test")
    return True


def test_format_option_short():
    """Test -f short option works."""
    returncode, stdout, stderr = run_command(['-f', 'json'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Format short option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Format short option test: -f not recognized")
        return False

    print("[PASS] Format short option test")
    return True


def test_invalid_format():
    """Test that invalid format values are rejected."""
    returncode, stdout, stderr = run_command(['--format', 'invalid'])

    if returncode != 2:
        print(f"[FAIL] Invalid format test: Expected return code 2, got {returncode}")
        return False

    if 'invalid choice' not in stderr.lower():
        print("[FAIL] Invalid format test: Expected 'invalid choice' in error message")
        return False

    print("[PASS] Invalid format test")
    return True


def test_namespace_option():
    """Test --namespace option is accepted."""
    returncode, stdout, stderr = run_command(['--namespace', 'default'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Namespace option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Namespace option test: --namespace not recognized")
        return False

    print("[PASS] Namespace option test")
    return True


def test_namespace_option_short():
    """Test -n short option works."""
    returncode, stdout, stderr = run_command(['-n', 'kube-system'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Namespace short option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Namespace short option test: -n not recognized")
        return False

    print("[PASS] Namespace short option test")
    return True


def test_warn_only_option():
    """Test --warn-only option is accepted."""
    returncode, stdout, stderr = run_command(['--warn-only'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Warn-only option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Warn-only option test: --warn-only not recognized")
        return False

    print("[PASS] Warn-only option test")
    return True


def test_warn_only_short():
    """Test -w short option works."""
    returncode, stdout, stderr = run_command(['-w'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Warn-only short option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Warn-only short option test: -w not recognized")
        return False

    print("[PASS] Warn-only short option test")
    return True


def test_verbose_option():
    """Test --verbose option is accepted."""
    returncode, stdout, stderr = run_command(['--verbose'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Verbose option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Verbose option test: --verbose not recognized")
        return False

    print("[PASS] Verbose option test")
    return True


def test_verbose_short():
    """Test -v short option works."""
    returncode, stdout, stderr = run_command(['-v'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Verbose short option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Verbose short option test: -v not recognized")
        return False

    print("[PASS] Verbose short option test")
    return True


def test_include_system_option():
    """Test --include-system option is accepted."""
    returncode, stdout, stderr = run_command(['--include-system'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Include-system option test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Include-system option test: --include-system not recognized")
        return False

    print("[PASS] Include-system option test")
    return True


def test_combined_options():
    """Test combining multiple options."""
    returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default'])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Combined options test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Combined options test: Options not recognized")
        return False

    print("[PASS] Combined options test")
    return True


def test_combined_options_long():
    """Test combining long form options."""
    returncode, stdout, stderr = run_command([
        '--format', 'table',
        '--warn-only',
        '--namespace', 'kube-system',
        '--verbose',
        '--include-system'
    ])

    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Combined long options test: Unexpected return code {returncode}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Combined long options test: Options not recognized")
        return False

    print("[PASS] Combined long options test")
    return True


def test_kubectl_not_found_error():
    """Test graceful handling when kubectl is not found or fails."""
    returncode, stdout, stderr = run_command([])

    # Should exit with error code 1 or 2 if kubectl is not available
    if returncode not in [0, 1, 2]:
        print(f"[FAIL] Kubectl error handling test: Unexpected return code {returncode}")
        return False

    # If kubectl not found, error message should be helpful
    if returncode == 2 and 'kubectl' not in stderr.lower():
        print("[FAIL] Kubectl error handling test: No kubectl mentioned in error")
        return False

    print("[PASS] Kubectl error handling test")
    return True


def test_no_arguments_runs():
    """Test that script runs with no arguments (uses defaults)."""
    returncode, stdout, stderr = run_command([])

    # Should attempt to run (will fail without kubectl, but args are valid)
    if returncode not in [0, 1, 2]:
        print(f"[FAIL] No arguments test: Unexpected return code {returncode}")
        return False

    print("[PASS] No arguments test")
    return True


def main():
    """Run all tests."""
    print("Running k8s_limitrange_auditor.py tests...")
    print()

    tests = [
        test_help_message,
        test_help_message_short,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_format_option_short,
        test_invalid_format,
        test_namespace_option,
        test_namespace_option_short,
        test_warn_only_option,
        test_warn_only_short,
        test_verbose_option,
        test_verbose_short,
        test_include_system_option,
        test_combined_options,
        test_combined_options_long,
        test_kubectl_not_found_error,
        test_no_arguments_runs,
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
            print(f"[FAIL] {test.__name__}: Exception: {e}")
            failed += 1

    print()
    total = passed + failed
    print(f"Test Results: {passed}/{total} tests passed")

    if failed > 0:
        print("Some tests failed!")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
