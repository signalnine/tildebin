#!/usr/bin/env python3
"""
Tests for cpu_frequency_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual cpufreq interface.
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
        'cpu_frequency_monitor.py',
        '--help'
    ])

    assert return_code == 0, f"Expected return code 0, got {return_code}"
    assert 'Monitor CPU frequency scaling' in stdout, "Description not found in help output"
    assert '--format' in stdout, "--format option not found"
    assert '--expected-governor' in stdout, "--expected-governor option not found"
    assert '--warn-only' in stdout, "--warn-only option not found"
    assert '--verbose' in stdout, "--verbose option not found"
    assert '--no-throttle-check' in stdout, "--no-throttle-check option not found"
    assert 'Examples:' in stdout, "Examples section not found"
    assert 'Exit codes:' in stdout, "Exit codes section not found"

    print("[PASS] Help message test")
    return True


def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'cpu_frequency_monitor.py',
            '--format', fmt
        ])

        # Script should run (may exit with 2 if cpufreq not available, which is OK)
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
        'cpu_frequency_monitor.py',
        '--format', 'invalid'
    ])

    assert return_code != 0, "Invalid format should cause non-zero exit code"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("[PASS] Invalid format test")
    return True


def test_expected_governor_flag():
    """Test that --expected-governor flag is recognized."""
    for governor in ['performance', 'powersave', 'ondemand', 'conservative', 'schedutil']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'cpu_frequency_monitor.py',
            '--expected-governor', governor
        ])

        # Should accept the argument (may exit with 2 if cpufreq not available)
        assert return_code in [0, 1, 2], \
            f"Governor {governor}: Unexpected return code {return_code}"
        assert 'unrecognized arguments' not in stderr.lower(), \
            f"Governor {governor}: Argument not recognized"

    print("[PASS] Expected governor flag test")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'cpu_frequency_monitor.py',
        '--warn-only'
    ])

    # Should accept the flag (may exit with 2 if cpufreq not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Warn-only flag test")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'cpu_frequency_monitor.py',
        '--verbose'
    ])

    # Should accept the flag (may exit with 2 if cpufreq not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Verbose flag test")
    return True


def test_no_throttle_check_flag():
    """Test that --no-throttle-check flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'cpu_frequency_monitor.py',
        '--no-throttle-check'
    ])

    # Should accept the flag (may exit with 2 if cpufreq not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] No-throttle-check flag test")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'cpu_frequency_monitor.py',
        '--format', 'json',
        '--expected-governor', 'performance',
        '--warn-only',
        '--verbose'
    ])

    # Should accept all flags (may exit with 2 if cpufreq not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags not recognized"

    print("[PASS] Combined flags test")
    return True


def test_json_output_format():
    """Test that JSON output is valid when cpufreq is available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'cpu_frequency_monitor.py',
        '--format', 'json'
    ])

    # If cpufreq is available (return code 0 or 1), stdout should be valid JSON
    if return_code in [0, 1]:
        import json
        try:
            data = json.loads(stdout)
            assert isinstance(data, list), "JSON output should be a list"
            if len(data) > 0:
                assert 'cpu' in data[0], "JSON objects should have 'cpu' field"
                assert 'governor' in data[0], "JSON objects should have 'governor' field"
                assert 'status' in data[0], "JSON objects should have 'status' field"
            print("[PASS] JSON output format test")
        except json.JSONDecodeError:
            print("[FAIL] JSON output format test: Invalid JSON")
            return False
    else:
        # cpufreq not available, which is fine for this test
        print("[SKIP] JSON output format test (cpufreq not available)")

    return True


def test_table_output_format():
    """Test that table output has proper formatting."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'cpu_frequency_monitor.py',
        '--format', 'table'
    ])

    # If cpufreq is available (return code 0 or 1), check table format
    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            # Should have header with column names
            assert 'CPU' in lines[0], "Table should have CPU column"
            assert 'Governor' in lines[0], "Table should have Governor column"
            assert 'Status' in lines[0], "Table should have Status column"
            print("[PASS] Table output format test")
    else:
        # cpufreq not available, which is fine for this test
        print("[SKIP] Table output format test (cpufreq not available)")

    return True


def test_missing_cpufreq_handling():
    """Test that script handles missing cpufreq gracefully."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'cpu_frequency_monitor.py'
    ])

    # Should either work (0, 1) or report missing cpufreq (2)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"

    if return_code == 2:
        # Should have error message about missing cpufreq
        assert 'CPU frequency scaling interface not available' in stderr or \
               'not available' in stderr.lower(), \
               "Should report missing cpufreq interface"

    print("[PASS] Missing cpufreq handling test")
    return True


def main():
    """Run all tests and report results."""
    tests = [
        test_help_message,
        test_format_options,
        test_invalid_format,
        test_expected_governor_flag,
        test_warn_only_flag,
        test_verbose_flag,
        test_no_throttle_check_flag,
        test_combined_flags,
        test_json_output_format,
        test_table_output_format,
        test_missing_cpufreq_handling,
    ]

    passed = 0
    failed = 0
    skipped = 0

    print("Running tests for cpu_frequency_monitor.py...\n")

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
