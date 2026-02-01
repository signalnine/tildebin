#!/usr/bin/env python3
"""
Tests for k8s_image_policy_auditor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual Kubernetes cluster access.
"""

import subprocess
import sys
import os


def run_command(cmd):
    """Run a command and return (return_code, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def test_help_message():
    """Test that --help flag works and shows usage information."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--help'
    ])

    if return_code != 0:
        print(f"[FAIL] Help message test: Expected return code 0, got {return_code}")
        return False

    if 'Audit Kubernetes workload' not in stdout:
        print("[FAIL] Help message test: Description not found in help output")
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

    if '--no-require-digest' not in stdout:
        print("[FAIL] Help message test: --no-require-digest option not found")
        return False

    if '--trusted-registry' not in stdout:
        print("[FAIL] Help message test: --trusted-registry option not found")
        return False

    if 'Examples:' not in stdout:
        print("[FAIL] Help message test: Examples section not found")
        return False

    print("[PASS] Help message test")
    return True


def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'k8s_image_policy_auditor.py',
            '--format', fmt
        ])

        # Script should run (may exit with 2 if kubectl not available, which is OK)
        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Format option test ({fmt}): Unexpected return code {return_code}")
            return False

        if 'invalid choice' in stderr.lower() or 'unrecognized arguments' in stderr.lower():
            print(f"[FAIL] Format option test ({fmt}): Format not recognized")
            return False

    print("[PASS] Format option test")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--warn-only'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Warn-only flag test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Warn-only flag test: Flag not recognized")
        return False

    print("[PASS] Warn-only flag test")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--verbose'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Verbose flag test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Verbose flag test: Flag not recognized")
        return False

    print("[PASS] Verbose flag test")
    return True


def test_namespace_option():
    """Test that --namespace option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--namespace', 'default'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Namespace option test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Namespace option test: --namespace option not recognized")
        return False

    print("[PASS] Namespace option test")
    return True


def test_no_require_digest_flag():
    """Test that --no-require-digest flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--no-require-digest'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] No-require-digest flag test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] No-require-digest flag test: Flag not recognized")
        return False

    print("[PASS] No-require-digest flag test")
    return True


def test_trusted_registry_option():
    """Test that --trusted-registry option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--trusted-registry', 'my-registry.example.com'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Trusted registry option test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Trusted registry option test: --trusted-registry option not recognized")
        return False

    print("[PASS] Trusted registry option test")
    return True


def test_skip_registry_check_flag():
    """Test that --skip-registry-check flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--skip-registry-check'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Skip registry check flag test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Skip registry check flag test: Flag not recognized")
        return False

    print("[PASS] Skip registry check flag test")
    return True


def test_combined_options():
    """Test that multiple options can be used together."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose',
        '--no-require-digest',
        '--trusted-registry', 'example.com'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Combined options test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Combined options test: Options not recognized")
        return False

    print("[PASS] Combined options test")
    return True


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--format', 'invalid'
    ])

    if return_code != 2:
        print(f"[FAIL] Invalid format test: Expected return code 2, got {return_code}")
        return False

    if 'invalid choice' not in stderr.lower():
        print("[FAIL] Invalid format test: Expected error message about invalid choice")
        return False

    print("[PASS] Invalid format test")
    return True


def test_no_kubectl_handling():
    """Test graceful handling when kubectl command is not available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py'
    ])

    # Should either work (0, 1) or report missing kubectl (2)
    if return_code not in [0, 1, 2]:
        print(f"[FAIL] No kubectl handling test: Unexpected return code {return_code}")
        return False

    # If kubectl not found, should have helpful error message
    if return_code == 2 and 'kubectl' in stderr.lower():
        if 'not found' not in stderr.lower() and 'install' not in stderr.lower():
            print("[FAIL] No kubectl handling test: Missing helpful message about kubectl")
            return False

    print("[PASS] No kubectl handling test")
    return True


def test_short_option_aliases():
    """Test that short option aliases work."""
    # Test -f for --format
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '-f', 'json'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short option alias test (-f): Unexpected return code {return_code}")
        return False

    # Test -w for --warn-only
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '-w'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short option alias test (-w): Unexpected return code {return_code}")
        return False

    # Test -n for --namespace
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '-n', 'default'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short option alias test (-n): Unexpected return code {return_code}")
        return False

    # Test -v for --verbose
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '-v'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short option alias test (-v): Unexpected return code {return_code}")
        return False

    print("[PASS] Short option alias test")
    return True


def test_multiple_trusted_registries():
    """Test that multiple --trusted-registry options can be specified."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_image_policy_auditor.py',
        '--trusted-registry', 'registry1.example.com',
        '--trusted-registry', 'registry2.example.com'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Multiple trusted registries test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Multiple trusted registries test: Multiple --trusted-registry not recognized")
        return False

    print("[PASS] Multiple trusted registries test")
    return True


def main():
    """Run all tests."""
    # Change to script directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(script_dir)

    print("Running k8s_image_policy_auditor.py tests...")
    print()

    tests = [
        test_help_message,
        test_format_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_namespace_option,
        test_no_require_digest_flag,
        test_trusted_registry_option,
        test_skip_registry_check_flag,
        test_combined_options,
        test_invalid_format,
        test_no_kubectl_handling,
        test_short_option_aliases,
        test_multiple_trusted_registries,
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
