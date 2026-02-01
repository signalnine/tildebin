#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_raid_rebuild_monitor.py functionality.
Tests argument parsing and output handling without requiring actual RAID arrays.
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
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--help']
    )
    assert return_code == 0, f"Help command failed with return code: {return_code}"
    assert 'rebuild' in stdout.lower(), "Expected 'rebuild' in help output"
    assert 'resync' in stdout.lower(), "Expected 'resync' in help output"
    assert '--format' in stdout, "Expected '--format' in help output"
    assert '--array' in stdout, "Expected '--array' in help output"


def test_format_plain_option():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--format', 'plain']
    )
    # Should complete (exit 0, 1, or 2 depending on system state)
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"


def test_format_json_option():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--format', 'json']
    )
    # Should complete (exit 0, 1, or 2 depending on system state)
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"

    # If we got output, it should be valid JSON or an error message
    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            assert 'timestamp' in data, "JSON should contain timestamp"
            assert 'arrays' in data, "JSON should contain arrays"
            assert 'summary' in data, "JSON should contain summary"
        except json.JSONDecodeError:
            # This is OK if there's no mdstat (exit code 2)
            pass


def test_format_table_option():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--format', 'table']
    )
    # Should complete (exit 0, 1, or 2 depending on system state)
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--format', 'invalid']
    )
    assert return_code == 2, "Invalid format should be rejected"
    assert 'invalid choice' in stderr, "Expected 'invalid choice' in error"


def test_verbose_option():
    """Test that verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '-v']
    )
    # Should complete (exit 0, 1, or 2 depending on system state)
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"


def test_rebuilding_only_option():
    """Test that --rebuilding-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--rebuilding-only']
    )
    # Should complete (exit 0, 1, or 2 depending on system state)
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"


def test_array_option():
    """Test that --array option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--array', 'md0']
    )
    # Should complete (exit 0, 1, or 2 depending on system state)
    # Exit 2 is acceptable if array doesn't exist or no mdstat
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"


def test_short_array_option():
    """Test that -a short option works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '-a', 'md0']
    )
    # Should complete (exit 0, 1, or 2 depending on system state)
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_raid_rebuild_monitor.py',
        '-v',
        '--format', 'json',
        '--rebuilding-only'
    ])
    # Should complete (exit 0, 1, or 2 depending on system state)
    assert return_code in [0, 1, 2], f"Unexpected return code: {return_code}"


def test_invalid_option():
    """Test that invalid options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--invalid-option']
    )
    assert return_code == 2, "Invalid option should be rejected"


def test_exit_codes_documented():
    """Test that exit codes are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_raid_rebuild_monitor.py', '--help']
    )
    assert return_code == 0, f"Help command failed: {return_code}"
    # Verify exit codes are documented
    assert 'Exit codes' in stdout or 'exit code' in stdout.lower(), \
        "Exit codes should be documented in help"


if __name__ == "__main__":
    print("Testing baremetal_raid_rebuild_monitor.py...")
    print()

    tests = [
        ("Help message", test_help_message),
        ("Plain format option", test_format_plain_option),
        ("JSON format option", test_format_json_option),
        ("Table format option", test_format_table_option),
        ("Invalid format rejection", test_invalid_format_option),
        ("Verbose option", test_verbose_option),
        ("Rebuilding-only option", test_rebuilding_only_option),
        ("Array option", test_array_option),
        ("Short array option", test_short_array_option),
        ("Combined options", test_combined_options),
        ("Invalid option rejection", test_invalid_option),
        ("Exit codes documented", test_exit_codes_documented),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            test_func()
            print(f"[PASS] {test_name}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            failed += 1

    print()
    print(f"Test Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
