#!/usr/bin/env python3
"""
Test script for baremetal_signal_disposition_monitor.py functionality.
Tests argument parsing, output formats, and error handling without requiring
specific system state or actual signal disposition issues.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
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
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--help']
    )

    if return_code == 0 and 'signal' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_basic_execution():
    """Test basic execution without arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py']
    )

    # Should succeed (0 = no issues) or have warnings (1 = issues found)
    # Should not be usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Basic execution test passed")
        return True
    else:
        print(f"[FAIL] Basic execution test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format and parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON format test failed - wrong return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        # Check expected structure
        if 'total_concerning' in data and 'processes' in data:
            if isinstance(data['processes'], list):
                print("[PASS] JSON output format test passed")
                return True
            else:
                print(f"[FAIL] JSON processes field is not a list")
                return False
        else:
            print(f"[FAIL] JSON missing expected fields")
            print(f"  Keys found: {list(data.keys())}")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--format', 'table']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Check for table formatting characters or signal-related content
        if '+' in stdout or '|' in stdout or 'signal' in stdout.lower() or 'disposition' in stdout.lower():
            print("[PASS] Table output format test passed")
            return True
        else:
            print(f"[FAIL] Table format missing expected formatting")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Table format test failed - wrong return code: {return_code}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--format', 'plain']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Should have signal-related output
        if 'signal' in stdout.lower() or 'process' in stdout.lower():
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain format missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Plain format test failed - wrong return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should return exit code 2, got {return_code}")
        return False


def test_verbose_flag():
    """Test verbose output flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--verbose']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed - return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test --warn-only flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--warn-only']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] --warn-only flag test failed - return code: {return_code}")
        return False


def test_no_blocked_flag():
    """Test --no-blocked flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--no-blocked']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --no-blocked flag test passed")
        return True
    else:
        print(f"[FAIL] --no-blocked flag test failed - return code: {return_code}")
        return False


def test_no_ignored_flag():
    """Test --no-ignored flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--no-ignored']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --no-ignored flag test passed")
        return True
    else:
        print(f"[FAIL] --no-ignored flag test failed - return code: {return_code}")
        return False


def test_conflicting_no_flags():
    """Test that --no-blocked and --no-ignored together are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py',
         '--no-blocked', '--no-ignored']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Conflicting --no-blocked/--no-ignored rejection test passed")
        return True
    else:
        print(f"[FAIL] Conflicting flags should return exit code 2, got {return_code}")
        return False


def test_high_only_flag():
    """Test --high-only flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--high-only']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --high-only flag test passed")
        return True
    else:
        print(f"[FAIL] --high-only flag test failed - return code: {return_code}")
        return False


def test_user_filter():
    """Test --user filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--user', 'root']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --user filter test passed")
        return True
    else:
        print(f"[FAIL] --user filter test failed - return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py',
         '--format', 'json', '--verbose', '--high-only']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] Combined options test failed - return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        print("[PASS] Combined options test passed")
        return True
    except json.JSONDecodeError:
        print(f"[FAIL] Combined options produced invalid JSON")
        return False


def test_json_structure_complete():
    """Test that JSON output has all expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON structure test failed - wrong return code")
        return False

    try:
        data = json.loads(stdout)
        required_fields = ['total_concerning', 'high_severity_count',
                          'medium_severity_count', 'processes']
        missing = [f for f in required_fields if f not in data]

        if missing:
            print(f"[FAIL] JSON structure missing fields: {missing}")
            return False

        # Verify types
        if not isinstance(data['total_concerning'], int):
            print("[FAIL] total_concerning should be int")
            return False
        if not isinstance(data['high_severity_count'], int):
            print("[FAIL] high_severity_count should be int")
            return False
        if not isinstance(data['medium_severity_count'], int):
            print("[FAIL] medium_severity_count should be int")
            return False
        if not isinstance(data['processes'], list):
            print("[FAIL] processes should be list")
            return False

        print("[PASS] JSON structure complete test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_short_flags():
    """Test short flag versions."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '-v', '-w']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Short flags test passed")
        return True
    else:
        print(f"[FAIL] Short flags test failed - return code: {return_code}")
        return False


def test_nonexistent_user():
    """Test filter with non-existent user (should still run, just find nothing)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py',
         '--user', 'nonexistent_user_12345']
    )

    # Should succeed with no results (exit code 0)
    if return_code == 0:
        print("[PASS] Non-existent user filter test passed")
        return True
    else:
        print(f"[FAIL] Non-existent user should return exit code 0, got {return_code}")
        return False


def test_help_contains_expected_content():
    """Test that help message contains expected signal-related content."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_signal_disposition_monitor.py', '--help']
    )

    if return_code != 0:
        print(f"[FAIL] Help should return exit code 0")
        return False

    expected_terms = ['SIGTERM', 'blocked', 'ignored', 'format']
    found = [term for term in expected_terms if term.lower() in stdout.lower()]

    if len(found) >= 3:  # At least 3 of 4 expected terms
        print("[PASS] Help content test passed")
        return True
    else:
        print(f"[FAIL] Help missing expected terms. Found: {found}")
        return False


if __name__ == '__main__':
    print("Testing baremetal_signal_disposition_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_basic_execution,
        test_json_output_format,
        test_table_output_format,
        test_plain_output_format,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_no_blocked_flag,
        test_no_ignored_flag,
        test_conflicting_no_flags,
        test_high_only_flag,
        test_user_filter,
        test_combined_options,
        test_json_structure_complete,
        test_short_flags,
        test_nonexistent_user,
        test_help_contains_expected_content,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)
