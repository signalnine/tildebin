#!/usr/bin/env python3
"""
Test script for k8s_priority_class_analyzer.py functionality.
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
        [sys.executable, 'k8s_priority_class_analyzer.py', '--help']
    )

    if return_code == 0 and 'priority' in stdout.lower() and 'namespace' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_help_short_flag():
    """Test that -h flag works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '-h']
    )

    if return_code == 0 and 'priority' in stdout.lower():
        print("[PASS] Help short flag test passed")
        return True
    else:
        print(f"[FAIL] Help short flag test failed")
        return False


def test_invalid_format_option():
    """Test that invalid format options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_format_options_recognized():
    """Test that format options are recognized by argparse"""
    formats = ['plain', 'json', 'table']
    passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_priority_class_analyzer.py', '--format', fmt]
        )

        # Should not fail with argument parsing error
        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Format option '{fmt}' not recognized")
            passed = False

    if passed:
        print("[PASS] Format options recognized test passed")
    return passed


def test_namespace_option():
    """Test that namespace option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '-n', 'default']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print(f"[FAIL] Namespace option test failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_namespace_long_option():
    """Test that --namespace option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--namespace', 'kube-system']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Namespace long option test passed")
        return True
    else:
        print(f"[FAIL] Namespace long option test failed")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '-v']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        return False


def test_verbose_long_flag():
    """Test that --verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--verbose']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose long flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose long flag test failed")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '-w']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        return False


def test_warn_only_long_flag():
    """Test that --warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--warn-only']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only long flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only long flag test failed")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py',
         '--format', 'json',
         '-n', 'default',
         '-v']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_kubectl_not_found_handling():
    """Test that missing kubectl is handled gracefully"""
    # Temporarily modify PATH to hide kubectl
    import os
    old_path = os.environ.get('PATH', '')
    os.environ['PATH'] = '/nonexistent'

    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py']
    )

    os.environ['PATH'] = old_path

    # Should exit with code 2 and mention kubectl
    if return_code == 2 and 'kubectl' in stderr.lower():
        print("[PASS] kubectl not found handling test passed")
        return True
    else:
        print(f"[FAIL] kubectl not found handling test failed")
        print(f"  Return code: {return_code} (expected 2)")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_exit_codes_valid():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py']
    )

    # Valid exit codes: 0 (success), 1 (warnings), 2 (kubectl missing or error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_docstring_present():
    """Test that script has module-level docstring with exit codes"""
    with open('k8s_priority_class_analyzer.py', 'r') as f:
        content = f.read()

    if '"""' in content and 'Exit codes:' in content and 'PriorityClass' in content:
        print("[PASS] Docstring test passed")
        return True
    else:
        print("[FAIL] Docstring missing or incomplete")
        return False


def test_shebang_present():
    """Test that script has proper shebang"""
    with open('k8s_priority_class_analyzer.py', 'r') as f:
        first_line = f.readline()

    if first_line.startswith('#!/usr/bin/env python3'):
        print("[PASS] Shebang test passed")
        return True
    else:
        print("[FAIL] Shebang missing or incorrect")
        return False


def test_help_includes_examples():
    """Test that help message includes usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help includes examples test passed")
        return True
    else:
        print("[FAIL] Help should include examples")
        return False


def test_help_mentions_preemption():
    """Test that help message mentions preemption policy"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--help']
    )

    if return_code == 0 and 'preempt' in stdout.lower():
        print("[PASS] Help mentions preemption test passed")
        return True
    else:
        print("[FAIL] Help should mention preemption")
        return False


def test_argparse_setup():
    """Test that argparse is correctly configured"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--invalid-option']
    )

    # Should fail with usage error (exit code 2 from argparse)
    if return_code == 2 and 'unrecognized arguments' in stderr:
        print("[PASS] Argparse setup test passed")
        return True
    else:
        print(f"[FAIL] Argparse setup test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_import():
    """Test that json module is imported correctly"""
    return_code, stdout, stderr = run_command(
        [sys.executable, '-c',
         'import k8s_priority_class_analyzer; print("OK")']
    )

    # May fail if kubectl is not available, but should not fail on import
    if 'ModuleNotFoundError' not in stderr and 'ImportError' not in stderr:
        print("[PASS] Module import test passed")
        return True
    else:
        print(f"[FAIL] Module import failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_script_executable_check():
    """Test that script can be invoked"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_priority_class_analyzer.py', '--help']
    )

    if return_code == 0:
        print("[PASS] Script executable test passed")
        return True
    else:
        print(f"[FAIL] Script not executable")
        return False


if __name__ == "__main__":
    print(f"Testing k8s_priority_class_analyzer.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_help_short_flag,
        test_invalid_format_option,
        test_format_options_recognized,
        test_namespace_option,
        test_namespace_long_option,
        test_verbose_flag,
        test_verbose_long_flag,
        test_warn_only_flag,
        test_warn_only_long_flag,
        test_combined_options,
        test_kubectl_not_found_handling,
        test_exit_codes_valid,
        test_docstring_present,
        test_shebang_present,
        test_help_includes_examples,
        test_help_mentions_preemption,
        test_argparse_setup,
        test_json_import,
        test_script_executable_check,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
