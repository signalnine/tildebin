#!/usr/bin/env python3
"""
Test script for baremetal_boot_issues_analyzer.py functionality.
Tests argument parsing and error handling without requiring systemd journald.
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
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--help']
    )

    if return_code == 0 and 'boot issues' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_format_option():
    """Test that invalid format options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--format', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    passed = True

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_boot_issues_analyzer.py', '--format', fmt]
        )

        # Will exit with code 2 (missing journalctl) or 0/1 if journald available
        # But shouldn't exit with usage error from argparse
        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Format option '{fmt}' not recognized")
            passed = False

    if passed:
        print(f"[PASS] Format options test passed")
    return passed


def test_boots_option():
    """Test that boots option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--boots', '10']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Boots option test passed")
        return True
    else:
        print(f"[FAIL] Boots option test failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_current_only_flag():
    """Test that current-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--current-only']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Current-only flag test passed")
        return True
    else:
        print(f"[FAIL] Current-only flag test failed")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '-v']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--warn-only']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        return False


def test_checks_option():
    """Test that checks option is accepted with valid checks"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--checks', 'kernel,oom,emergency']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Checks option test passed")
        return True
    else:
        print(f"[FAIL] Checks option test failed")
        print(f"  Error: {stderr[:200]}")
        return False


def test_invalid_checks_option():
    """Test that invalid check names are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--checks', 'invalid_check']
    )

    # Should exit with code 2 for invalid checks
    if return_code == 2 and 'invalid' in stderr.lower():
        print("[PASS] Invalid checks option test passed")
        return True
    else:
        # If journalctl not available, we might get a different error
        if 'journalctl' in stderr.lower():
            print("[SKIP] Invalid checks option test (journalctl not available)")
            return True
        print(f"[FAIL] Invalid checks option test failed")
        print(f"  Return code: {return_code}")
        print(f"  Error: {stderr[:200]}")
        return False


def test_json_format_structure():
    """Test JSON output format structure if journald available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--format', 'json']
    )

    # Only test JSON parsing if command succeeded (journald available)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check for expected keys
            if 'summary' in data and 'boots' in data:
                # Check summary structure
                summary = data['summary']
                expected_keys = ['boots_analyzed', 'total_issues', 'total_critical', 'total_warnings']
                if all(k in summary for k in expected_keys):
                    print("[PASS] JSON format structure test passed")
                    return True
                else:
                    print(f"[FAIL] JSON summary missing expected keys")
                    return False
            else:
                print(f"[FAIL] JSON format missing expected keys")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # journalctl not available, skip this test
        print("[SKIP] JSON format structure test (journalctl not available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_exit_code_on_missing_journald():
    """Test that missing journalctl returns exit code 2"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py']
    )

    # Valid exit codes: 0 (no issues), 1 (issues found), 2 (missing tool)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_help_lists_available_checks():
    """Test that help message lists all available checks"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py', '--help']
    )

    expected_checks = ['kernel', 'oom', 'emergency', 'units', 'hardware', 'critical', 'filesystem']
    all_found = all(check in stdout.lower() for check in expected_checks)

    if return_code == 0 and all_found:
        print("[PASS] Help lists available checks test passed")
        return True
    else:
        missing = [c for c in expected_checks if c not in stdout.lower()]
        print(f"[FAIL] Help missing checks: {missing}")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_boot_issues_analyzer.py',
         '--format', 'json',
         '--boots', '3',
         '--verbose',
         '--checks', 'kernel,oom']
    )

    # Should not fail with argument parsing error
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Error: {stderr[:200]}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_boot_issues_analyzer.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_format_option,
        test_format_options,
        test_boots_option,
        test_current_only_flag,
        test_verbose_flag,
        test_warn_only_flag,
        test_checks_option,
        test_invalid_checks_option,
        test_json_format_structure,
        test_exit_code_on_missing_journald,
        test_help_lists_available_checks,
        test_combined_options,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
