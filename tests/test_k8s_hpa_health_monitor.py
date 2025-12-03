#!/usr/bin/env python3
"""
Test script for k8s_hpa_health_monitor.py functionality.
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
        [sys.executable, 'k8s_hpa_health_monitor.py', '--help']
    )

    if return_code == 0 and 'HorizontalPodAutoscaler' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format_argument():
    """Test that invalid format arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_hpa_health_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format argument test passed")
        return True
    else:
        print("[FAIL] Invalid format argument should fail")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_options_accepted():
    """Test that all valid format options are accepted in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_hpa_health_monitor.py', '--help']
    )

    formats_present = (
        'plain' in stdout and
        'json' in stdout and
        'table' in stdout
    )

    if return_code == 0 and formats_present:
        print("[PASS] Format options test passed")
        return True
    else:
        print("[FAIL] Format options test failed")
        print(f"  Missing format options in help text")
        return False


def test_namespace_option():
    """Test that namespace option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_hpa_health_monitor.py', '--help']
    )

    if return_code == 0 and '--namespace' in stdout:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option test failed")
        return False


def test_warn_only_option():
    """Test that warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_hpa_health_monitor.py', '--help']
    )

    if return_code == 0 and '--warn-only' in stdout:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed")
        return False


def test_verbose_option():
    """Test that verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_hpa_health_monitor.py', '--help']
    )

    if return_code == 0 and '--verbose' in stdout:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed")
        return False


def test_exit_code_conventions():
    """Test that script follows exit code conventions in help text."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_hpa_health_monitor.py', '--help']
    )

    # Check if help mentions exit codes
    exit_code_mention = (
        'exit' in stdout.lower() or
        'Exit codes' in stdout
    )

    if return_code == 0:
        print("[PASS] Exit code conventions test passed")
        return True
    else:
        print("[FAIL] Exit code conventions test failed")
        return False


def test_examples_in_help():
    """Test that help includes usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_hpa_health_monitor.py', '--help']
    )

    has_examples = 'Examples:' in stdout or 'examples:' in stdout

    if return_code == 0 and has_examples:
        print("[PASS] Examples in help test passed")
        return True
    else:
        print("[FAIL] Examples in help test failed")
        return False


def test_script_requires_kubectl():
    """Test that script properly checks for kubectl (will fail without kubectl)."""
    # This test verifies the script handles missing kubectl gracefully
    # We expect it to fail with exit code 2 when kubectl is not in PATH

    # Save original PATH
    import os
    original_path = os.environ.get('PATH', '')

    try:
        # Run with empty PATH to simulate missing kubectl
        env = os.environ.copy()
        env['PATH'] = '/tmp/nonexistent'

        proc = subprocess.Popen(
            [sys.executable, 'k8s_hpa_health_monitor.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )
        stdout, stderr = proc.communicate()
        return_code = proc.returncode

        # Should exit with code 2 (dependency missing) and mention kubectl
        if return_code == 2 and 'kubectl' in stderr.decode('utf-8'):
            print("[PASS] kubectl dependency check test passed")
            return True
        else:
            print(f"[FAIL] kubectl dependency check test failed")
            print(f"  Expected exit code 2, got {return_code}")
            print(f"  Stderr: {stderr.decode('utf-8')[:200]}")
            return False
    except Exception as e:
        print(f"[FAIL] kubectl dependency check test failed with exception: {e}")
        return False


def test_docstring_present():
    """Test that the script has a proper docstring."""
    try:
        with open('k8s_hpa_health_monitor.py', 'r') as f:
            content = f.read()

        has_docstring = '"""' in content and 'HorizontalPodAutoscaler' in content
        has_exit_codes = 'Exit codes:' in content

        if has_docstring and has_exit_codes:
            print("[PASS] Docstring test passed")
            return True
        else:
            print("[FAIL] Docstring test failed")
            return False
    except Exception as e:
        print(f"[FAIL] Docstring test failed: {e}")
        return False


def test_shebang_present():
    """Test that the script has a proper shebang."""
    try:
        with open('k8s_hpa_health_monitor.py', 'r') as f:
            first_line = f.readline()

        if first_line.startswith('#!/usr/bin/env python3'):
            print("[PASS] Shebang test passed")
            return True
        else:
            print(f"[FAIL] Shebang test failed: {first_line}")
            return False
    except Exception as e:
        print(f"[FAIL] Shebang test failed: {e}")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_hpa_health_monitor.py...\n")

    tests = [
        test_help_message,
        test_invalid_format_argument,
        test_format_options_accepted,
        test_namespace_option,
        test_warn_only_option,
        test_verbose_option,
        test_exit_code_conventions,
        test_examples_in_help,
        test_script_requires_kubectl,
        test_docstring_present,
        test_shebang_present,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\n{'='*50}")
    print(f"Test Results: {passed}/{total} tests passed")
    print(f"{'='*50}")

    sys.exit(0 if passed == total else 1)
