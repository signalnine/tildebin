#!/usr/bin/env python3
"""
Tests for baremetal_thermal_throttle_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual thermal throttle interface.
"""

import subprocess
import sys


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
        'baremetal_thermal_throttle_monitor.py',
        '--help'
    ])

    assert return_code == 0, f"Expected return code 0, got {return_code}"
    assert 'thermal throttling' in stdout.lower(), "Description not found in help output"
    assert '--format' in stdout, "--format option not found"
    assert '--warn-only' in stdout, "--warn-only option not found"
    assert '--verbose' in stdout, "--verbose option not found"
    assert '--threshold' in stdout, "--threshold option not found"
    assert 'Examples:' in stdout, "Examples section not found"
    assert 'Exit codes:' in stdout, "Exit codes section not found"

    print("[PASS] Help message test")
    return True


def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'baremetal_thermal_throttle_monitor.py',
            '--format', fmt
        ])

        # Script should run (may exit with 2 if thermal throttle not available)
        assert return_code in [0, 1, 2], f"Format {fmt}: Unexpected return code {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt}: Format not recognized"
        assert 'unrecognized arguments' not in stderr.lower(), f"Format {fmt}: Argument error"

    print("[PASS] Format option test")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--format', 'invalid'
    ])

    assert return_code != 0, "Invalid format should cause non-zero exit code"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("[PASS] Invalid format test")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--warn-only'
    ])

    # Should accept the flag (may exit with 2 if thermal throttle not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Warn-only flag test")
    return True


def test_warn_only_short_flag():
    """Test that -w short flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '-w'
    ])

    # Should accept the flag (may exit with 2 if thermal throttle not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Warn-only short flag test")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--verbose'
    ])

    # Should accept the flag (may exit with 2 if thermal throttle not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Verbose flag test")
    return True


def test_verbose_short_flag():
    """Test that -v short flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '-v'
    ])

    # Should accept the flag (may exit with 2 if thermal throttle not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Verbose short flag test")
    return True


def test_threshold_option():
    """Test that --threshold option is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--threshold', '10'
    ])

    # Should accept the option (may exit with 2 if thermal throttle not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Argument not recognized"

    print("[PASS] Threshold option test")
    return True


def test_invalid_threshold():
    """Test that invalid threshold value is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--threshold', 'notanumber'
    ])

    assert return_code != 0, "Invalid threshold should cause non-zero exit code"
    assert 'invalid' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid threshold"

    print("[PASS] Invalid threshold test")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose',
        '--threshold', '5'
    ])

    # Should accept all flags (may exit with 2 if thermal throttle not available)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags not recognized"

    print("[PASS] Combined flags test")
    return True


def test_json_output_format():
    """Test that JSON output is valid when thermal throttle is available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--format', 'json'
    ])

    # If thermal throttle is available (return code 0 or 1), stdout should be valid JSON
    if return_code in [0, 1]:
        import json
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dict"
            assert 'summary' in data, "JSON should have 'summary' field"
            assert 'cpus' in data, "JSON should have 'cpus' field"
            assert 'status' in data['summary'], "Summary should have 'status' field"
            assert 'total_core_throttles' in data['summary'], \
                "Summary should have 'total_core_throttles' field"
            assert 'total_package_throttles' in data['summary'], \
                "Summary should have 'total_package_throttles' field"
            print("[PASS] JSON output format test")
        except json.JSONDecodeError:
            print("[FAIL] JSON output format test: Invalid JSON")
            return False
    else:
        # Thermal throttle not available, which is fine for this test
        print("[SKIP] JSON output format test (thermal throttle not available)")

    return True


def test_table_output_format():
    """Test that table output has proper formatting."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py',
        '--format', 'table'
    ])

    # If thermal throttle is available (return code 0 or 1), check table format
    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            # Should have header with column names
            header = lines[0]
            assert 'CPU' in header, "Table should have CPU column"
            assert 'Core Throttles' in header or 'Throttle' in header, \
                "Table should have throttle columns"
            print("[PASS] Table output format test")
    else:
        # Thermal throttle not available, which is fine for this test
        print("[SKIP] Table output format test (thermal throttle not available)")

    return True


def test_missing_thermal_throttle_handling():
    """Test that script handles missing thermal throttle gracefully."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py'
    ])

    # Should either work (0, 1) or report missing thermal throttle (2)
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"

    if return_code == 2:
        # Should have error message about missing thermal throttle
        assert 'thermal throttle' in stderr.lower() or \
               'not available' in stderr.lower(), \
               "Should report missing thermal throttle interface"

    print("[PASS] Missing thermal throttle handling test")
    return True


def test_no_throttling_exit_code():
    """Test that exit code 0 is returned when no throttling detected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_throttle_monitor.py'
    ])

    # If the script runs successfully with no throttling, should return 0
    # If throttling detected, should return 1
    # If interface not available, should return 2
    assert return_code in [0, 1, 2], f"Unexpected return code {return_code}"

    if return_code == 0:
        # Verify no throttling message or empty throttle counts
        assert 'no thermal throttling' in stdout.lower() or \
               'ok' in stdout.lower() or \
               '"status": "OK"' in stdout, \
               "Should indicate no throttling when exit code is 0"

    print("[PASS] No throttling exit code test")
    return True


def main():
    """Run all tests and report results."""
    tests = [
        test_help_message,
        test_format_options,
        test_invalid_format,
        test_warn_only_flag,
        test_warn_only_short_flag,
        test_verbose_flag,
        test_verbose_short_flag,
        test_threshold_option,
        test_invalid_threshold,
        test_combined_flags,
        test_json_output_format,
        test_table_output_format,
        test_missing_thermal_throttle_handling,
        test_no_throttling_exit_code,
    ]

    passed = 0
    failed = 0

    print("Running tests for baremetal_thermal_throttle_monitor.py...\n")

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
