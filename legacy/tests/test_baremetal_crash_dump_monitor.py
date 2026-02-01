#!/usr/bin/env python3
"""
Test script for baremetal_crash_dump_monitor.py functionality.
Tests argument parsing, output formats, and error handling without requiring
actual crash dumps or kdump service.
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
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--help']
    )

    if return_code == 0 and 'crash' in stdout.lower() and 'kdump' in stdout.lower():
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
        [sys.executable, 'baremetal_crash_dump_monitor.py']
    )

    # Should succeed (0 = healthy) or have warnings (1 = issues found)
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
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON format test failed - wrong return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        # Check expected structure
        expected_keys = ['kdump_service', 'crashkernel', 'crash_directories', 'issues', 'check_time']
        missing_keys = [k for k in expected_keys if k not in data]

        if missing_keys:
            print(f"[FAIL] JSON missing expected keys: {missing_keys}")
            return False

        # Verify nested structures
        if not isinstance(data['kdump_service'], dict):
            print("[FAIL] kdump_service should be a dict")
            return False
        if not isinstance(data['crash_directories'], list):
            print("[FAIL] crash_directories should be a list")
            return False
        if not isinstance(data['issues'], list):
            print("[FAIL] issues should be a list")
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
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--format', 'table']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Check for table formatting characters
        if '─' in stdout or '│' in stdout or 'Crash' in stdout:
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
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--format', 'plain']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        # Should have crash-related output
        if 'Crash' in stdout or 'crash' in stdout.lower() or 'Kdump' in stdout:
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
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--verbose']
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
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--warn-only']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] --warn-only flag test failed - return code: {return_code}")
        return False


def test_recent_days_option():
    """Test --recent-days option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--recent-days', '7']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --recent-days option test passed")
        return True
    else:
        print(f"[FAIL] --recent-days option test failed - return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_recent_days():
    """Test that invalid recent-days value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--recent-days', '0']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Invalid recent-days rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid recent-days (0) should return exit code 2, got {return_code}")
        return False


def test_non_numeric_recent_days():
    """Test that non-numeric recent-days is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--recent-days', 'abc']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Non-numeric recent-days rejection test passed")
        return True
    else:
        print(f"[FAIL] Non-numeric recent-days should return exit code 2, got {return_code}")
        return False


def test_check_dmesg_flag():
    """Test --check-dmesg flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--check-dmesg']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] --check-dmesg flag test passed")
        return True
    else:
        print(f"[FAIL] --check-dmesg flag test failed - return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py',
         '--format', 'json', '--verbose', '--recent-days', '14']
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


def test_json_structure_kdump():
    """Test that JSON output has correct kdump_service structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON kdump structure test failed - wrong return code")
        return False

    try:
        data = json.loads(stdout)
        kdump = data.get('kdump_service', {})
        required_fields = ['installed', 'enabled', 'active', 'status']
        missing = [f for f in required_fields if f not in kdump]

        if missing:
            print(f"[FAIL] kdump_service missing fields: {missing}")
            return False

        print("[PASS] JSON kdump structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_structure_crashkernel():
    """Test that JSON output has correct crashkernel structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON crashkernel structure test failed - wrong return code")
        return False

    try:
        data = json.loads(stdout)
        crashkernel = data.get('crashkernel', {})
        required_fields = ['reserved']
        missing = [f for f in required_fields if f not in crashkernel]

        if missing:
            print(f"[FAIL] crashkernel missing fields: {missing}")
            return False

        if not isinstance(crashkernel['reserved'], bool):
            print(f"[FAIL] crashkernel 'reserved' should be boolean")
            return False

        print("[PASS] JSON crashkernel structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_short_flags():
    """Test short flag versions."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py', '-v', '-w']
    )

    # Should succeed (0) or have warnings (1), but not usage error (2)
    if return_code in [0, 1]:
        print("[PASS] Short flags test passed")
        return True
    else:
        print(f"[FAIL] Short flags test failed - return code: {return_code}")
        return False


def test_check_dmesg_json():
    """Test that --check-dmesg adds dmesg_analysis to JSON output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_crash_dump_monitor.py',
         '--format', 'json', '--check-dmesg']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] check-dmesg JSON test failed - wrong return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        if 'dmesg_analysis' not in data:
            print(f"[FAIL] JSON should contain dmesg_analysis when --check-dmesg used")
            return False

        dmesg = data['dmesg_analysis']
        if 'checked' not in dmesg or 'indicators' not in dmesg:
            print(f"[FAIL] dmesg_analysis missing expected fields")
            return False

        print("[PASS] check-dmesg JSON test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


if __name__ == '__main__':
    print("Testing baremetal_crash_dump_monitor.py...")
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
        test_recent_days_option,
        test_invalid_recent_days,
        test_non_numeric_recent_days,
        test_check_dmesg_flag,
        test_combined_options,
        test_json_structure_kdump,
        test_json_structure_crashkernel,
        test_short_flags,
        test_check_dmesg_json,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)
