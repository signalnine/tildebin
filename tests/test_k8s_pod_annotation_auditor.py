#!/usr/bin/env python3
"""
Test script for k8s_pod_annotation_auditor.py functionality.
Tests argument parsing and error handling without requiring actual Kubernetes access.
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
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py', '--help'
    ])

    if return_code == 0 and 'annotation' in stdout.lower() and 'audit' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed - return code: {return_code}")
        print(f"stdout: {stdout[:200]}")
        return False


def test_required_option_recognized():
    """Test that the --required option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--required', 'app.kubernetes.io/owner'
    ])

    # Should fail due to missing kubectl, but argument should be recognized
    # Exit code 2 means kubectl missing, 1 means execution issue
    if return_code in [1, 2]:
        print("[PASS] Required option test passed")
        return True
    else:
        print(f"[FAIL] Required option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_missing_required_option():
    """Test that script fails when --required is not provided."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py'
    ])

    # Should fail with exit code 2 and mention --required
    if return_code == 2 and '--required' in stderr:
        print("[PASS] Missing required option test passed")
        return True
    else:
        print(f"[FAIL] Missing required option test failed - return code: {return_code}")
        print(f"stderr: {stderr[:200]}")
        return False


def test_namespace_option():
    """Test that the --namespace option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '-n', 'default',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print(f"[FAIL] Namespace option test failed with return code: {return_code}")
        return False


def test_format_plain():
    """Test that plain format option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--format', 'plain',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print(f"[FAIL] Format plain option test failed with return code: {return_code}")
        return False


def test_format_json():
    """Test that JSON format option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--format', 'json',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Format JSON option test passed")
        return True
    else:
        print(f"[FAIL] Format JSON option test failed with return code: {return_code}")
        return False


def test_format_table():
    """Test that table format option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--format', 'table',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Format table option test passed")
        return True
    else:
        print(f"[FAIL] Format table option test failed with return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--format', 'invalid',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_warn_only_option():
    """Test that the --warn-only option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '-w',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed with return code: {return_code}")
        return False


def test_verbose_option():
    """Test that the --verbose option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '-v',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        return False


def test_include_system_option():
    """Test that the --include-system option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--include-system',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Include-system option test passed")
        return True
    else:
        print(f"[FAIL] Include-system option test failed with return code: {return_code}")
        return False


def test_forbidden_option():
    """Test that the --forbidden option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--forbidden', 'deprecated.example.com/old-config',
        '--required', 'app.kubernetes.io/owner'
    ])

    if return_code in [1, 2]:
        print("[PASS] Forbidden option test passed")
        return True
    else:
        print(f"[FAIL] Forbidden option test failed with return code: {return_code}")
        return False


def test_multiple_required_annotations():
    """Test that multiple required annotations can be specified."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--required', 'app.kubernetes.io/owner,prometheus.io/scrape'
    ])

    if return_code in [1, 2]:
        print("[PASS] Multiple required annotations test passed")
        return True
    else:
        print(f"[FAIL] Multiple required annotations test failed with return code: {return_code}")
        return False


def test_annotation_with_regex_pattern():
    """Test that annotation with regex pattern can be specified."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--required', 'app.kubernetes.io/owner=team-.*'
    ])

    if return_code in [1, 2]:
        print("[PASS] Annotation with regex pattern test passed")
        return True
    else:
        print(f"[FAIL] Annotation with regex pattern test failed with return code: {return_code}")
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '-n', 'production',
        '-v',
        '-w',
        '--format', 'json',
        '--required', 'app.kubernetes.io/owner=team-.*,prometheus.io/scrape=(true|false)',
        '--forbidden', 'deprecated.example.com/old-config',
        '--include-system'
    ])

    if return_code in [1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with return code: {return_code}")
        return False


def test_kubectl_missing_message():
    """Test that missing kubectl produces helpful error message."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'k8s_pod_annotation_auditor.py',
        '--required', 'app.kubernetes.io/owner'
    ])

    # If kubectl is missing, should exit 2 with helpful message
    # If kubectl is present, any exit code is fine
    if return_code == 2:
        if 'kubectl' in stderr.lower():
            print("[PASS] kubectl missing message test passed")
            return True
        else:
            print("[FAIL] Missing kubectl should mention kubectl")
            return False
    else:
        # kubectl is present, test passes
        print("[PASS] kubectl missing message test passed (kubectl present)")
        return True


if __name__ == "__main__":
    print("Testing k8s_pod_annotation_auditor.py...")

    tests = [
        test_help_message,
        test_required_option_recognized,
        test_missing_required_option,
        test_namespace_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_warn_only_option,
        test_verbose_option,
        test_include_system_option,
        test_forbidden_option,
        test_multiple_required_annotations,
        test_annotation_with_regex_pattern,
        test_combined_options,
        test_kubectl_missing_message,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
