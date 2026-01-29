#!/usr/bin/env python3
"""
Tests for baremetal_thermal_zone_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual thermal zones (works on any system).
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
        'baremetal_thermal_zone_monitor.py',
        '--help'
    ])

    if return_code != 0:
        print(f"[FAIL] Help message test: Expected return code 0, got {return_code}")
        return False

    if 'thermal zone' not in stdout.lower():
        print("[FAIL] Help message test: 'thermal zone' not found in help output")
        return False

    if '--format' not in stdout:
        print("[FAIL] Help message test: --format option not found")
        return False

    if '--warn-only' not in stdout:
        print("[FAIL] Help message test: --warn-only option not found")
        return False

    if '--verbose' not in stdout:
        print("[FAIL] Help message test: --verbose option not found")
        return False

    if 'Examples:' not in stdout:
        print("[FAIL] Help message test: Examples section not found")
        return False

    if 'Exit codes:' not in stdout:
        print("[FAIL] Help message test: Exit codes section not found")
        return False

    print("[PASS] Help message test")
    return True


def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'baremetal_thermal_zone_monitor.py',
            '--format', fmt
        ])

        # Script should run (may exit with 0, 1, or 2 depending on system)
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
        'baremetal_thermal_zone_monitor.py',
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
        'baremetal_thermal_zone_monitor.py',
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


def test_combined_options():
    """Test that multiple options can be used together."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_zone_monitor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose'
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
        'baremetal_thermal_zone_monitor.py',
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


def test_json_output_structure():
    """Test that JSON output is valid and has expected structure."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_zone_monitor.py',
        '--format', 'json'
    ])

    # If thermal zones exist, output should be valid JSON
    if return_code in [0, 1]:
        import json
        try:
            data = json.loads(stdout)
            if 'thermal_zones' not in data:
                print("[FAIL] JSON output test: 'thermal_zones' key missing")
                return False
            if 'cooling_devices' not in data:
                print("[FAIL] JSON output test: 'cooling_devices' key missing")
                return False
            if not isinstance(data['thermal_zones'], list):
                print("[FAIL] JSON output test: thermal_zones should be a list")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON output test: Invalid JSON - {e}")
            return False

    print("[PASS] JSON output structure test")
    return True


def test_no_thermal_zones_handling():
    """Test graceful handling when thermal zones are not available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_zone_monitor.py'
    ])

    # Should either work (0, 1) or report missing thermal zones (2)
    if return_code not in [0, 1, 2]:
        print(f"[FAIL] No thermal zones handling test: Unexpected return code {return_code}")
        return False

    # If exit 2, should have helpful error message
    if return_code == 2:
        if 'thermal' not in stderr.lower():
            print("[FAIL] No thermal zones handling test: Missing helpful error message")
            return False

    print("[PASS] No thermal zones handling test")
    return True


def test_short_flags():
    """Test that short flags work."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_thermal_zone_monitor.py',
        '-f', 'json',
        '-w',
        '-v'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short flags test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Short flags test: Short flags not recognized")
        return False

    print("[PASS] Short flags test")
    return True


def main():
    """Run all tests."""
    # Change to script directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(script_dir)

    print("Running baremetal_thermal_zone_monitor.py tests...")
    print()

    tests = [
        test_help_message,
        test_format_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_combined_options,
        test_invalid_format,
        test_json_output_structure,
        test_no_thermal_zones_handling,
        test_short_flags,
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
