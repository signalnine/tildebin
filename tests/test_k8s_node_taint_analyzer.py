#!/usr/bin/env python3
"""
Test script for k8s_node_taint_analyzer.py functionality.
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
        [sys.executable, 'k8s_node_taint_analyzer.py', '--help']
    )

    if return_code == 0 and 'node taints' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format_argument():
    """Test that invalid format argument is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_taint_analyzer.py', '--format', 'invalid']
    )

    # Should fail with exit code 2 (usage error) or non-zero
    if return_code != 0:
        print("[PASS] Invalid format argument test passed")
        return True
    else:
        print("[FAIL] Invalid format argument should fail")
        return False


def test_format_option_parsing():
    """Test that format options are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_node_taint_analyzer.py', '--format', fmt]
        )

        # Will fail due to missing kubectl, but should recognize the format option
        # Check that error is about kubectl, not format option
        if 'kubectl not found' in stderr or 'kubectl' in stderr.lower():
            continue
        elif return_code == 2 and 'invalid choice' in stderr:
            print(f"[FAIL] Format option '{fmt}' not recognized")
            return False

    print("[PASS] Format option parsing test passed")
    return True


def test_verbose_flag():
    """Test that verbose flag is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_taint_analyzer.py', '-v']
    )

    # Will fail due to missing kubectl, but verbose flag should be accepted
    # Check error is about kubectl, not about -v flag
    if 'kubectl not found' in stderr or 'kubectl' in stderr.lower():
        print("[PASS] Verbose flag test passed")
        return True
    elif 'unrecognized arguments: -v' in stderr:
        print("[FAIL] Verbose flag not recognized")
        return False
    else:
        # Some other error, still counts as pass for flag recognition
        print("[PASS] Verbose flag test passed (other error)")
        return True


def test_warn_only_flag():
    """Test that warn-only flag is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_taint_analyzer.py', '--warn-only']
    )

    # Will fail due to missing kubectl, but warn-only flag should be accepted
    if 'kubectl not found' in stderr or 'kubectl' in stderr.lower():
        print("[PASS] Warn-only flag test passed")
        return True
    elif 'unrecognized arguments' in stderr:
        print("[FAIL] Warn-only flag not recognized")
        return False
    else:
        print("[PASS] Warn-only flag test passed (other error)")
        return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_taint_analyzer.py',
         '--format', 'json', '-v', '--warn-only']
    )

    # Will fail due to missing kubectl, but all flags should be accepted
    if 'kubectl not found' in stderr or 'kubectl' in stderr.lower():
        print("[PASS] Combined flags test passed")
        return True
    elif 'unrecognized arguments' in stderr:
        print(f"[FAIL] Combined flags not recognized")
        print(f"  Error: {stderr[:200]}")
        return False
    else:
        print("[PASS] Combined flags test passed (other error)")
        return True


def test_kubectl_missing_error():
    """Test that script handles missing kubectl gracefully."""
    # Temporarily override PATH to ensure kubectl is not found
    import os
    env = os.environ.copy()
    env['PATH'] = '/nonexistent'

    try:
        proc = subprocess.Popen(
            [sys.executable, 'k8s_node_taint_analyzer.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )
        stdout, stderr = proc.communicate()
        return_code = proc.returncode
        stderr_text = stderr.decode('utf-8')

        # Should exit with code 2 (dependency missing) and helpful error
        if return_code == 2 and 'kubectl not found' in stderr_text:
            print("[PASS] kubectl missing error test passed")
            return True
        else:
            print(f"[FAIL] kubectl missing error test failed")
            print(f"  Expected exit code 2, got {return_code}")
            print(f"  stderr: {stderr_text[:200]}")
            return False
    except Exception as e:
        print(f"[FAIL] kubectl missing error test failed with exception: {e}")
        return False


def test_short_flag_aliases():
    """Test that short flag aliases work."""
    # Test -v for --verbose
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_taint_analyzer.py', '-v']
    )

    if 'unrecognized arguments: -v' in stderr:
        print("[FAIL] Short flag -v not recognized")
        return False

    # Test -w for --warn-only
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_taint_analyzer.py', '-w']
    )

    if 'unrecognized arguments: -w' in stderr:
        print("[FAIL] Short flag -w not recognized")
        return False

    print("[PASS] Short flag aliases test passed")
    return True


def test_help_contains_examples():
    """Test that help message includes usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_taint_analyzer.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain examples section")
        return False


def test_help_contains_exit_codes():
    """Test that help message or docstring mentions exit codes."""
    # Read the script file to check docstring
    try:
        with open('k8s_node_taint_analyzer.py', 'r') as f:
            content = f.read(1000)  # Read first 1000 chars

        if 'Exit codes:' in content or 'exit code' in content.lower():
            print("[PASS] Exit codes documentation test passed")
            return True
        else:
            print("[FAIL] Script should document exit codes")
            return False
    except Exception as e:
        print(f"[FAIL] Could not read script file: {e}")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_node_taint_analyzer.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format_argument,
        test_format_option_parsing,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_flags,
        test_kubectl_missing_error,
        test_short_flag_aliases,
        test_help_contains_examples,
        test_help_contains_exit_codes,
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
            print(f"[ERROR] Test {test.__name__} raised exception: {e}")
            failed += 1
        print()

    print("=" * 60)
    print(f"Test Results: {passed}/{len(tests)} tests passed")

    if failed > 0:
        print(f"              {failed} tests failed")

    sys.exit(0 if failed == 0 else 1)
