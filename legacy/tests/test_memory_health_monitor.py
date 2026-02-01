#!/usr/bin/env python3
"""
Tests for memory_health_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual hardware EDAC support.
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
        'memory_health_monitor.py',
        '--help'
    ])

    if return_code != 0:
        print(f"[FAIL] Help message test: Expected return code 0, got {return_code}")
        return False

    if 'Monitor memory health and ECC errors' not in stdout:
        print("[FAIL] Help message test: Description not found in help output")
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

    print("[PASS] Help message test")
    return True


def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'memory_health_monitor.py',
            '--format', fmt
        ])

        # Script should run (may exit with 0, 1, or 2)
        # We're just testing that the argument is parsed correctly
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
        'memory_health_monitor.py',
        '--warn-only'
    ])

    # Should accept the flag (exit 0, 1, or 2)
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
        'memory_health_monitor.py',
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
        'memory_health_monitor.py',
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
        'memory_health_monitor.py',
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


def test_basic_execution():
    """Test basic execution without arguments."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'memory_health_monitor.py'
    ])

    # Should either work (0, 1) or report missing data (2)
    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Basic execution test: Unexpected return code {return_code}")
        return False

    # On most systems, at least /proc/meminfo should be available
    # If it works, should have some output
    if return_code in [0, 1]:
        if not stdout or len(stdout) < 10:
            print("[FAIL] Basic execution test: Expected some output")
            return False

    print("[PASS] Basic execution test")
    return True


def test_json_output():
    """Test JSON output format."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'memory_health_monitor.py',
        '--format', 'json'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] JSON output test: Unexpected return code {return_code}")
        return False

    # If successful, output should be valid JSON-like
    if return_code in [0, 1]:
        if '{' not in stdout:
            print("[FAIL] JSON output test: Expected JSON output")
            return False

    print("[PASS] JSON output test")
    return True


def test_table_output():
    """Test table output format."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'memory_health_monitor.py',
        '--format', 'table'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Table output test: Unexpected return code {return_code}")
        return False

    print("[PASS] Table output test")
    return True


def test_warn_only_with_json():
    """Test combining --warn-only with JSON output."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'memory_health_monitor.py',
        '--warn-only',
        '--format', 'json'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Warn-only with JSON test: Unexpected return code {return_code}")
        return False

    print("[PASS] Warn-only with JSON test")
    return True


def main():
    """Run all tests."""
    # Change to script directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(script_dir)

    print("Running memory_health_monitor.py tests...")
    print()

    tests = [
        test_help_message,
        test_format_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_combined_options,
        test_invalid_format,
        test_basic_execution,
        test_json_output,
        test_table_output,
        test_warn_only_with_json,
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
