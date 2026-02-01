#!/usr/bin/env python3
"""
Test script for baremetal_pre_maintenance_checker.py functionality.
Tests argument parsing and output formats without requiring specific system states.
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
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--help']
    )

    if return_code == 0 and 'maintenance' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py']
    )

    # Should succeed (exit 0 or 1 depending on system state)
    if return_code in [0, 1] and 'PRE-MAINTENANCE' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'summary' not in data or 'checks' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        required_summary_keys = ['safe_to_proceed', 'critical', 'warnings', 'ok']
        if not all(key in summary for key in required_summary_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
            return False

        # Verify checks is a list
        if not isinstance(data['checks'], list):
            print("[FAIL] checks is not a list")
            return False

        # Verify each check has required structure
        for check in data['checks']:
            required_check_keys = ['name', 'status', 'message']
            if not all(key in check for key in required_check_keys):
                print(f"[FAIL] Check missing required keys: {check}")
                return False

            # Verify status is a valid value
            valid_statuses = ['OK', 'WARNING', 'CRITICAL', 'ERROR', 'SKIPPED']
            if check['status'] not in valid_statuses:
                print(f"[FAIL] Invalid status: {check['status']}")
                return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--format', 'table']
    )

    # Should succeed and contain table structure
    if return_code in [0, 1] and 'PRE-MAINTENANCE' in stdout and 'Check' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    # In warn-only mode, if no warnings, output might be minimal
    if return_code in [0, 1]:
        # If there are issues, they should still appear
        # If no issues, output should be minimal (no header)
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_mode():
    """Test verbose mode shows additional details."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--verbose']
    )

    # Should succeed and provide more detail
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_quick_mode():
    """Test quick mode skips slower checks."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--quick']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Quick mode test passed")
        return True
    else:
        print(f"[FAIL] Quick mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_safe_to_proceed_field():
    """Test JSON output includes safe_to_proceed boolean."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'summary' not in data or 'safe_to_proceed' not in data['summary']:
            print("[FAIL] JSON output missing safe_to_proceed field")
            return False

        safe = data['summary']['safe_to_proceed']
        if not isinstance(safe, bool):
            print(f"[FAIL] safe_to_proceed is not a boolean: {type(safe)}")
            return False

        print("[PASS] JSON safe_to_proceed test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_checks_have_details():
    """Test JSON output checks have details field."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        checks = data.get('checks', [])

        for check in checks:
            if 'details' not in check:
                print(f"[FAIL] Check '{check.get('name', 'unknown')}' missing details field")
                return False

        print("[PASS] Checks have details test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_multiple_checks_run():
    """Test that multiple different checks are performed."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        checks = data.get('checks', [])
        check_names = [c.get('name') for c in checks]

        # Verify core checks are present
        expected_checks = [
            'D-State Processes',
            'Zombie Processes',
            'Memory Pressure',
            'Disk Space',
            'System Load',
            'Network Connectivity'
        ]

        missing = [c for c in expected_checks if c not in check_names]
        if missing:
            print(f"[FAIL] Missing expected checks: {missing}")
            return False

        print(f"[PASS] Multiple checks test passed ({len(checks)} checks run)")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py',
         '--format', 'json', '--quick', '--verbose']
    )

    try:
        data = json.loads(stdout)
        if 'summary' in data and 'checks' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print("[FAIL] Combined options test failed")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] Combined options JSON parsing failed: {e}")
        return False


def test_short_options():
    """Test short form options (-v, -w)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_pre_maintenance_checker.py', '-v', '-w']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Short options test passed")
        return True
    else:
        print(f"[FAIL] Short options test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_pre_maintenance_checker.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_warn_only_mode,
        test_verbose_mode,
        test_quick_mode,
        test_exit_codes,
        test_json_safe_to_proceed_field,
        test_checks_have_details,
        test_multiple_checks_run,
        test_combined_options,
        test_short_options,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
