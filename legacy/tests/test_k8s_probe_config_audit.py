#!/usr/bin/env python3
"""
Test script for k8s_probe_config_audit.py functionality.
Tests argument parsing and error handling without requiring kubectl.
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
        [sys.executable, 'k8s_probe_config_audit.py', '--help']
    )

    # Check for key terms in help message
    expected_terms = ['probe', 'liveness', 'readiness', 'namespace', 'format']
    found_terms = [term for term in expected_terms if term.lower() in stdout.lower()]

    if return_code == 0 and len(found_terms) >= 4:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Found terms: {found_terms}")
        print(f"  Output: {stdout[:300]}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--format', 'invalid']
    )

    if return_code != 0 and ('invalid choice' in stderr or 'error' in stderr.lower()):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_options():
    """Test that all format options are recognized"""
    formats = ['plain', 'json', 'table']
    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_probe_config_audit.py', '--format', fmt]
        )

        # Will fail with kubectl error, but format option should be accepted
        if 'invalid choice' not in stderr and 'unrecognized arguments' not in stderr:
            print(f"[PASS] Format option '{fmt}' recognized")
        else:
            print(f"[FAIL] Format option '{fmt}' not recognized")
            print(f"  Stderr: {stderr[:200]}")
            return False

    return True


def test_namespace_option():
    """Test that namespace option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--namespace', 'test-namespace']
    )

    # Will fail with kubectl error, but namespace option should be accepted
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Namespace option test passed")
        return True
    else:
        print("[FAIL] Namespace option not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--verbose']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_include_system_flag():
    """Test that include-system flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--include-system']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Include-system flag test passed")
        return True
    else:
        print("[FAIL] Include-system flag not recognized")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_kubectl_missing_error():
    """Test graceful handling when kubectl is not found"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py']
    )

    # Should exit with error code (1 or 2) when kubectl unavailable
    if return_code != 0:
        if 'kubectl' in stderr.lower() or 'error' in stderr.lower():
            print("[PASS] kubectl missing error test passed")
            return True
        else:
            print("[PASS] Script exits with error when kubectl unavailable")
            return True
    else:
        print("[FAIL] Script should fail when kubectl is unavailable")
        return False


def test_short_flags():
    """Test that short flags work"""
    tests = [
        (['-n', 'test'], "namespace short flag"),
        (['-v'], "verbose short flag"),
        (['-w'], "warn-only short flag"),
    ]

    for args, description in tests:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_probe_config_audit.py'] + args
        )

        if 'unrecognized arguments' not in stderr:
            print(f"[PASS] {description} test passed")
        else:
            print(f"[FAIL] {description} not recognized")
            print(f"  Stderr: {stderr[:200]}")
            return False

    return True


def test_combined_flags():
    """Test that multiple flags can be combined"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py',
         '-n', 'test-ns', '--format', 'json', '-v', '-w', '--include-system']
    )

    if 'unrecognized arguments' not in stderr and 'invalid choice' not in stderr:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print("[FAIL] Combined flags not accepted")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_shows_probe_checks():
    """Test that help message documents probe checks"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--help']
    )

    # Check that key probe checks are documented
    checks = ['liveness', 'readiness', 'startup', 'timeout', 'missing']
    found = [check for check in checks if check.lower() in stdout.lower()]

    if return_code == 0 and len(found) >= 3:
        print(f"[PASS] Help documents probe checks: {found}")
        return True
    else:
        print(f"[FAIL] Help should document probe checks")
        print(f"  Found: {found}")
        return False


def test_json_format_structure():
    """Test that JSON format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--format', 'json']
    )

    # Just verify the format option is accepted
    if 'invalid choice' not in stderr and 'unrecognized arguments' not in stderr:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option not accepted")
        return False


def test_exit_codes_documented():
    """Test that exit codes are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--help']
    )

    if 'exit code' in stdout.lower() or 'exit codes' in stdout.lower():
        print("[PASS] Exit codes documented in help")
        return True
    else:
        print("[FAIL] Exit codes should be documented in help")
        return False


def test_severity_levels_mentioned():
    """Test that severity levels are mentioned in help or code behavior"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_probe_config_audit.py', '--help']
    )

    # Check for severity terms
    severity_terms = ['high', 'medium', 'low', 'severity']
    found = [term for term in severity_terms if term.lower() in stdout.lower()]

    if len(found) >= 2:
        print(f"[PASS] Severity levels documented: {found}")
        return True
    else:
        print(f"[FAIL] Severity levels should be documented")
        print(f"  Found: {found}")
        return False


if __name__ == '__main__':
    print("Testing k8s_probe_config_audit.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format,
        test_format_options,
        test_namespace_option,
        test_verbose_flag,
        test_warn_only_flag,
        test_include_system_flag,
        test_kubectl_missing_error,
        test_short_flags,
        test_combined_flags,
        test_help_shows_probe_checks,
        test_json_format_structure,
        test_exit_codes_documented,
        test_severity_levels_mentioned,
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
            print(f"[FAIL] {test.__name__} raised exception: {e}")
            failed += 1
        print()

    total = passed + failed
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    if failed > 0:
        print(f"FAILED: {failed} test(s) failed")
        sys.exit(1)
    else:
        print("SUCCESS: All tests passed")
        sys.exit(0)
