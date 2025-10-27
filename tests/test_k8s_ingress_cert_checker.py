#!/usr/bin/env python3
"""
Tests for k8s_ingress_cert_checker.py
"""

import subprocess
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_command(cmd_args):
    """Helper to run command and capture output"""
    result = subprocess.run(cmd_args, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_help_message():
    """Test that help message is available and informative"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--help']
    )

    if returncode == 0 and 'Kubernetes Ingress' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed: {stderr}")
        return False


def test_invalid_namespace_flag():
    """Test that missing namespace argument is handled"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--namespace']
    )

    if returncode != 0:
        print("[PASS] Missing namespace argument test passed")
        return True
    else:
        print("[FAIL] Missing namespace argument should fail")
        return False


def test_invalid_format():
    """Test that invalid format argument is rejected"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--format', 'invalid']
    )

    if returncode != 0:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_valid_format_options():
    """Test that valid format options are accepted (won't run without kubectl)"""
    returncode1, _, _ = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--format', 'plain']
    )
    returncode2, _, _ = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--format', 'json']
    )

    # Both should fail with kubectl not found (exit code 2) or no ingresses
    # but format should be accepted
    if returncode1 == 2 or returncode1 == 1:
        print("[PASS] Valid format options test passed")
        return True
    else:
        print("[FAIL] Valid format should be accepted")
        return False


def test_warn_only_flag():
    """Test that --warn-only flag is recognized"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--warn-only']
    )

    # Should fail with kubectl not found or other k8s error, but flag should be accepted
    if returncode != 0:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag should be recognized")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-n', 'default', '-f', 'json', '-w']
    )

    # Should fail gracefully with kubectl error
    if returncode == 2 or returncode == 1:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print("[FAIL] Combined flags should be accepted")
        return False


def test_script_has_docstring():
    """Test that script has a module docstring"""
    with open('k8s_ingress_cert_checker.py', 'r') as f:
        content = f.read()
        if '"""' in content and 'Kubernetes Ingress' in content:
            print("[PASS] Script has proper docstring")
            return True
        else:
            print("[FAIL] Script missing docstring")
            return False


def test_script_imports():
    """Test that script imports key modules"""
    with open('k8s_ingress_cert_checker.py', 'r') as f:
        content = f.read()
        required_imports = ['argparse', 'json', 'subprocess', 'sys', 'datetime']
        missing = [imp for imp in required_imports if f'import {imp}' not in content]

        if not missing:
            print("[PASS] Script imports check passed")
            return True
        else:
            print(f"[FAIL] Script missing imports: {missing}")
            return False


def main():
    """Run all tests"""
    tests = [
        test_help_message,
        test_invalid_namespace_flag,
        test_invalid_format,
        test_valid_format_options,
        test_warn_only_flag,
        test_combined_flags,
        test_script_has_docstring,
        test_script_imports,
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
            print(f"[ERROR] {test.__name__} raised exception: {e}")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
