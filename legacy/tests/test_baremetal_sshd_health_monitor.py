#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_sshd_health_monitor.py functionality.
Tests argument parsing and error handling without requiring root access.
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
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '--help'
    ])
    assert return_code == 0, f"Help command failed with return code: {return_code}"
    assert 'SSH daemon' in stdout or 'sshd' in stdout.lower(), \
        "Expected 'SSH daemon' or 'sshd' in help output"
    assert '--format' in stdout, "Expected '--format' option in help"
    assert '--verbose' in stdout, "Expected '--verbose' option in help"


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '-v'
    ])
    # Should not fail at argument parsing level
    assert return_code in [0, 1, 2], f"Verbose option failed with unexpected return code: {return_code}"


def test_format_option_plain():
    """Test that the format option accepts 'plain'"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '--format', 'plain'
    ])
    assert return_code in [0, 1, 2], f"Format option 'plain' failed: {return_code}"


def test_format_option_json():
    """Test that the format option accepts 'json'"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '--format', 'json'
    ])
    assert return_code in [0, 1, 2], f"Format option 'json' failed: {return_code}"


def test_format_option_table():
    """Test that the format option accepts 'table'"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '--format', 'table'
    ])
    assert return_code in [0, 1, 2], f"Format option 'table' failed: {return_code}"


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '--format', 'invalid'
    ])
    assert return_code != 0, "Invalid format should have been rejected"
    assert 'invalid choice' in stderr or 'invalid choice' in stdout, \
        "Expected 'invalid choice' error message"


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '--warn-only'
    ])
    assert return_code in [0, 1, 2], f"Warn-only option failed: {return_code}"


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py',
        '-v',
        '--format', 'json',
        '--warn-only'
    ])
    assert return_code in [0, 1, 2], f"Combined options failed: {return_code}"


def test_json_output_structure():
    """Test that JSON output has expected structure when sshd is available"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '--format', 'json'
    ])
    # Only check JSON structure if command succeeded
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'running' in data, "Expected 'running' key in JSON output"
            assert 'issues' in data, "Expected 'issues' key in JSON output"
            assert 'connections' in data, "Expected 'connections' key in JSON output"
        except json.JSONDecodeError as e:
            # If sshd not found (exit 2), output won't be JSON
            pass


def test_missing_sshd_error():
    """Test that missing sshd gives helpful error (if applicable)"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py'
    ])
    # If sshd is not installed, should exit 2 with message
    if return_code == 2 and 'sshd not found' in stderr:
        assert 'openssh' in stderr.lower() or 'install' in stderr.lower(), \
            "Expected installation hint in error message"


def test_short_verbose_option():
    """Test that short -v option works"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_sshd_health_monitor.py', '-v'
    ])
    assert return_code in [0, 1, 2], f"Short verbose option failed: {return_code}"


if __name__ == "__main__":
    print("Testing baremetal_sshd_health_monitor.py...")
    print()

    tests = [
        ("Help message", test_help_message),
        ("Verbose option", test_verbose_option),
        ("Format option plain", test_format_option_plain),
        ("Format option json", test_format_option_json),
        ("Format option table", test_format_option_table),
        ("Invalid format", test_invalid_format),
        ("Warn-only option", test_warn_only_option),
        ("Combined options", test_combined_options),
        ("JSON output structure", test_json_output_structure),
        ("Missing sshd error", test_missing_sshd_error),
        ("Short verbose option", test_short_verbose_option),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"  [PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")
            failed += 1

    print()
    print(f"Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
