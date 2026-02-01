#!/usr/bin/env python3
"""
Tests for baremetal_tmpfs_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring special permissions or tmpfs configuration.
"""

import subprocess
import sys
import os
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
        'baremetal_tmpfs_monitor.py',
        '--help'
    ])

    if return_code != 0:
        print(f"[FAIL] Help message test: Expected return code 0, got {return_code}")
        return False

    if 'Monitor tmpfs filesystem usage' not in stdout:
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

    if '--warn' not in stdout:
        print("[FAIL] Help message test: --warn threshold option not found")
        return False

    if '--critical' not in stdout:
        print("[FAIL] Help message test: --critical threshold option not found")
        return False

    if '--mountpoint' not in stdout:
        print("[FAIL] Help message test: --mountpoint option not found")
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
            'baremetal_tmpfs_monitor.py',
            '--format', fmt
        ])

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
        'baremetal_tmpfs_monitor.py',
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
        'baremetal_tmpfs_monitor.py',
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


def test_threshold_options():
    """Test that threshold options are recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--warn', '70',
        '--critical', '85'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Threshold options test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Threshold options test: Options not recognized")
        return False

    print("[PASS] Threshold options test")
    return True


def test_invalid_threshold_range():
    """Test that invalid threshold range is rejected."""
    # warn >= critical should fail
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--warn', '90',
        '--critical', '80'
    ])

    if return_code != 2:
        print(f"[FAIL] Invalid threshold range test: Expected return code 2, got {return_code}")
        return False

    if 'less than' not in stderr.lower():
        print("[FAIL] Invalid threshold range test: Expected error about threshold order")
        return False

    print("[PASS] Invalid threshold range test")
    return True


def test_invalid_threshold_value():
    """Test that out-of-range threshold is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--warn', '150'
    ])

    if return_code != 2:
        print(f"[FAIL] Invalid threshold value test: Expected return code 2, got {return_code}")
        return False

    print("[PASS] Invalid threshold value test")
    return True


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
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
        'baremetal_tmpfs_monitor.py'
    ])

    # Should work (0 or 1) - most Linux systems have tmpfs
    if return_code not in [0, 1]:
        print(f"[FAIL] Basic execution test: Unexpected return code {return_code}")
        return False

    # Should have some output
    if not stdout or len(stdout) < 5:
        print("[FAIL] Basic execution test: Expected some output")
        return False

    print("[PASS] Basic execution test")
    return True


def test_json_output():
    """Test JSON output format is valid."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--format', 'json'
    ])

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON output test: Unexpected return code {return_code}")
        return False

    try:
        data = json.loads(stdout)
        if 'tmpfs_count' not in data:
            print("[FAIL] JSON output test: Missing tmpfs_count field")
            return False
        if 'filesystems' not in data:
            print("[FAIL] JSON output test: Missing filesystems field")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON output test: Invalid JSON output: {e}")
        return False

    print("[PASS] JSON output test")
    return True


def test_table_output():
    """Test table output format."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--format', 'table'
    ])

    if return_code not in [0, 1]:
        print(f"[FAIL] Table output test: Unexpected return code {return_code}")
        return False

    # Table should have header with column names
    if 'Mountpoint' not in stdout and 'No tmpfs' not in stdout:
        print("[FAIL] Table output test: Expected table header or no tmpfs message")
        return False

    print("[PASS] Table output test")
    return True


def test_nonexistent_mountpoint():
    """Test error handling for nonexistent mountpoint."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--mountpoint', '/nonexistent/path/12345'
    ])

    if return_code != 2:
        print(f"[FAIL] Nonexistent mountpoint test: Expected return code 2, got {return_code}")
        return False

    if 'not found' not in stderr.lower():
        print("[FAIL] Nonexistent mountpoint test: Expected error about mountpoint not found")
        return False

    print("[PASS] Nonexistent mountpoint test")
    return True


def test_combined_options():
    """Test that multiple options can be used together."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose',
        '--warn', '75',
        '--critical', '90'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Combined options test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Combined options test: Options not recognized")
        return False

    print("[PASS] Combined options test")
    return True


def test_short_flags():
    """Test short flag versions work."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '-w',  # --warn-only
        '-v'   # --verbose
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short flags test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Short flags test: Short flags not recognized")
        return False

    print("[PASS] Short flags test")
    return True


def test_devshm_monitoring():
    """Test monitoring /dev/shm specifically if it exists."""
    # Check if /dev/shm exists and is tmpfs
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_tmpfs_monitor.py',
        '--mountpoint', '/dev/shm'
    ])

    # Could be 0 (healthy), 1 (issues), or 2 (not found/not tmpfs)
    if return_code not in [0, 1, 2]:
        print(f"[FAIL] /dev/shm monitoring test: Unexpected return code {return_code}")
        return False

    print("[PASS] /dev/shm monitoring test")
    return True


def main():
    """Run all tests."""
    # Change to script directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(script_dir)

    print("Running baremetal_tmpfs_monitor.py tests...")
    print()

    tests = [
        test_help_message,
        test_format_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_threshold_options,
        test_invalid_threshold_range,
        test_invalid_threshold_value,
        test_invalid_format,
        test_basic_execution,
        test_json_output,
        test_table_output,
        test_nonexistent_mountpoint,
        test_combined_options,
        test_short_flags,
        test_devshm_monitoring,
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
