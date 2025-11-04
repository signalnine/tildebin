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


def test_short_flag_namespace():
    """Test that -n short flag works for namespace"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-n', 'kube-system']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Short namespace flag test passed")
        return True
    else:
        print("[FAIL] Short namespace flag should be accepted")
        return False


def test_short_flag_format():
    """Test that -f short flag works for format"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-f', 'plain']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Short format flag test passed")
        return True
    else:
        print("[FAIL] Short format flag should be accepted")
        return False


def test_short_flag_warn_only():
    """Test that -w short flag works for warn-only"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '-w']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print("[FAIL] Short warn-only flag should be accepted")
        return False


def test_days_option():
    """Test that --days option accepts numeric values"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--days', '30']
    )

    # Should fail with kubectl error but accept the flag
    if returncode in [1, 2]:
        print("[PASS] Days option test passed")
        return True
    else:
        print("[FAIL] Days option should accept numeric values")
        return False


def test_invalid_days_value():
    """Test that --days rejects non-numeric values"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py', '--days', 'invalid']
    )

    # Should fail with argument error
    if returncode == 2:
        print("[PASS] Invalid days value test passed")
        return True
    else:
        print("[FAIL] Invalid days value should be rejected")
        return False


def test_script_has_main_guard():
    """Test that script has proper __main__ guard"""
    with open('k8s_ingress_cert_checker.py', 'r') as f:
        content = f.read()
        if "if __name__ == '__main__':" in content or 'if __name__ == "__main__":' in content:
            print("[PASS] Script has main guard")
            return True
        else:
            print("[FAIL] Script missing main guard")
            return False


def test_no_args_runs():
    """Test that script runs with no arguments (uses defaults)"""
    returncode, stdout, stderr = run_command(
        [sys.executable, 'k8s_ingress_cert_checker.py']
    )

    # Should attempt to run (may fail with kubectl not found)
    if returncode in [0, 1, 2]:
        print("[PASS] No args test passed")
        return True
    else:
        print("[FAIL] Script should run with default arguments")
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
        test_short_flag_namespace,
        test_short_flag_format,
        test_short_flag_warn_only,
        test_days_option,
        test_invalid_days_value,
        test_script_has_main_guard,
        test_no_args_runs,
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

    total = passed + failed
    print(f"\nTest Results: {passed}/{total} tests passed")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
