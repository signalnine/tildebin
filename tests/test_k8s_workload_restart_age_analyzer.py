#!/usr/bin/env python3
"""
Tests for k8s_workload_restart_age_analyzer.py

These tests verify the script's argument parsing and basic functionality
without requiring actual Kubernetes cluster access.
"""

import subprocess
import sys
import json


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
        'k8s_workload_restart_age_analyzer.py',
        '--help'
    ])

    assert return_code == 0, f"Expected return code 0, got {return_code}"
    assert 'workload restart age' in stdout.lower(), "Description not found in help output"
    assert '--format' in stdout, "--format option not found"
    assert '--namespace' in stdout, "--namespace option not found"
    assert '--stale-days' in stdout, "--stale-days option not found"
    assert '--fresh-hours' in stdout, "--fresh-hours option not found"
    assert '--warn-only' in stdout, "--warn-only option not found"
    assert '--verbose' in stdout, "--verbose option not found"
    assert '--exclude-namespace' in stdout, "--exclude-namespace option not found"
    assert 'Examples:' in stdout, "Examples section not found"
    assert 'Exit codes:' in stdout, "Exit codes section not found"

    print("[PASS] Help message test")
    return True


def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'k8s_workload_restart_age_analyzer.py',
            '--format', fmt
        ])

        # Script should run (may exit with 2 if kubectl not available, which is OK)
        # We're just testing that the argument is parsed correctly
        assert return_code in [0, 1, 2], f"Format {fmt}: Unexpected return code {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt}: Format not recognized"
        assert 'unrecognized arguments' not in stderr.lower(), f"Format {fmt}: Argument error"

    print("[PASS] Format option test")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--format', 'invalid'
    ])

    assert return_code != 0, "Invalid format should cause non-zero exit code"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("[PASS] Invalid format test")
    return True


def test_namespace_flag():
    """Test that -n/--namespace flag is recognized."""
    for flag in ['-n', '--namespace']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'k8s_workload_restart_age_analyzer.py',
            flag, 'kube-system'
        ])

        # Should accept the argument (may exit with 2 if kubectl not available)
        assert return_code in [0, 1, 2], f"Flag {flag}: Unexpected return code {return_code}"
        assert 'unrecognized arguments' not in stderr.lower(), f"Flag {flag}: Argument not recognized"

    print("[PASS] Namespace flag test")
    return True


def test_stale_days_flag():
    """Test that --stale-days flag is recognized and accepts integers."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--stale-days', '14'
    ])

    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Stale days flag test")
    return True


def test_fresh_hours_flag():
    """Test that --fresh-hours flag is recognized and accepts integers."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--fresh-hours', '2'
    ])

    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Fresh hours flag test")
    return True


def test_warn_only_flag():
    """Test that -w/--warn-only flag is recognized."""
    for flag in ['-w', '--warn-only']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'k8s_workload_restart_age_analyzer.py',
            flag
        ])

        assert return_code in [0, 1, 2], f"Flag {flag}: Unexpected return code {return_code}"
        assert 'unrecognized arguments' not in stderr.lower(), f"Flag {flag}: Argument not recognized"

    print("[PASS] Warn-only flag test")
    return True


def test_verbose_flag():
    """Test that -v/--verbose flag is recognized."""
    for flag in ['-v', '--verbose']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'k8s_workload_restart_age_analyzer.py',
            flag
        ])

        assert return_code in [0, 1, 2], f"Flag {flag}: Unexpected return code {return_code}"
        assert 'unrecognized arguments' not in stderr.lower(), f"Flag {flag}: Argument not recognized"

    print("[PASS] Verbose flag test")
    return True


def test_exclude_namespace_flag():
    """Test that --exclude-namespace flag is recognized and can be repeated."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--exclude-namespace', 'kube-system',
        '--exclude-namespace', 'kube-public'
    ])

    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Exclude namespace flag test")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--format', 'json',
        '-n', 'default',
        '--stale-days', '7',
        '--fresh-hours', '2',
        '--warn-only',
        '--exclude-namespace', 'kube-system'
    ])

    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags not recognized"

    print("[PASS] Combined flags test")
    return True


def test_kubectl_missing_handling():
    """Test that script handles missing kubectl gracefully."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py'
    ])

    # Should either work (0, 1) or report missing kubectl (2)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"

    if return_code == 2:
        # Should have error message about missing kubectl
        assert 'kubectl' in stderr.lower() or 'not found' in stderr.lower(), \
            "Should report missing kubectl"

    print("[PASS] kubectl missing handling test")
    return True


def test_json_output_structure():
    """Test that JSON output has expected structure when kubectl is available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--format', 'json'
    ])

    # If kubectl is available (return code 0 or 1), validate JSON structure
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'summary' in data, "JSON output should have 'summary' field"
            assert 'total' in data['summary'], "Summary should have 'total' field"
            assert 'categories' in data, "JSON output should have 'categories' field"
            print("[PASS] JSON output structure test")
        except json.JSONDecodeError:
            print("[FAIL] JSON output structure test: Invalid JSON")
            return False
    else:
        # kubectl not available, which is fine for this test
        print("[SKIP] JSON output structure test (kubectl not available)")

    return True


def test_invalid_stale_days():
    """Test that non-integer stale-days is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--stale-days', 'abc'
    ])

    assert return_code != 0, "Invalid stale-days should cause non-zero exit code"
    assert 'invalid' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid argument"

    print("[PASS] Invalid stale-days test")
    return True


def test_invalid_fresh_hours():
    """Test that non-integer fresh-hours is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'k8s_workload_restart_age_analyzer.py',
        '--fresh-hours', 'xyz'
    ])

    assert return_code != 0, "Invalid fresh-hours should cause non-zero exit code"
    assert 'invalid' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid argument"

    print("[PASS] Invalid fresh-hours test")
    return True


def main():
    """Run all tests and report results."""
    tests = [
        test_help_message,
        test_format_options,
        test_invalid_format,
        test_namespace_flag,
        test_stale_days_flag,
        test_fresh_hours_flag,
        test_warn_only_flag,
        test_verbose_flag,
        test_exclude_namespace_flag,
        test_combined_flags,
        test_kubectl_missing_handling,
        test_json_output_structure,
        test_invalid_stale_days,
        test_invalid_fresh_hours,
    ]

    passed = 0
    failed = 0

    print("Running tests for k8s_workload_restart_age_analyzer.py...\n")

    for test in tests:
        try:
            result = test()
            if result:
                passed += 1
            else:
                failed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"Test Results: {passed} passed, {failed} failed")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
