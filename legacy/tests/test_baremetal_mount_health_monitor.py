#!/usr/bin/env python3
"""
Test script for baremetal_mount_health_monitor.py functionality.
Tests argument parsing and output formats without requiring special mount states.
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
        [sys.executable, 'baremetal_mount_health_monitor.py', '--help']
    )

    if return_code == 0 and 'mount' in stdout.lower() and 'health' in stdout.lower():
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
        [sys.executable, 'baremetal_mount_health_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_timeout_low():
    """Test that timeout below 1 is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--timeout', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid timeout (low) test passed")
        return True
    else:
        print(f"[FAIL] Invalid timeout should fail with exit code 2, got {return_code}")
        return False


def test_invalid_timeout_high():
    """Test that timeout above 60 is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--timeout', '120']
    )

    if return_code == 2:
        print("[PASS] Invalid timeout (high) test passed")
        return True
    else:
        print(f"[FAIL] Invalid timeout should fail with exit code 2, got {return_code}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py']
    )

    # Should succeed and contain mount summary
    if return_code in [0, 1] and ('mount' in stdout.lower() or 'healthy' in stdout.lower()):
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify expected structure
        if 'summary' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        required_keys = ['total_mounts', 'checked', 'healthy']
        if not all(key in summary for key in required_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
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
        [sys.executable, 'baremetal_mount_health_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1] and 'MOUNT HEALTH' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--verbose']
    )

    # Verbose mode should show mount details
    if return_code in [0, 1] and ('device' in stdout.lower() or 'type' in stdout.lower()):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on mount state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_skip_virtual_option():
    """Test --skip-virtual option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--skip-virtual', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # With skip-virtual, checked count should be less than or equal to total
            if data['summary']['checked'] <= data['summary']['total_mounts']:
                print("[PASS] Skip virtual option test passed")
                return True
            else:
                print("[FAIL] Checked count should be <= total")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print(f"[FAIL] Skip virtual test failed with exit code {return_code}")
        return False


def test_check_options_flag():
    """Test --check-options flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--check-options']
    )

    # Should succeed regardless of option issues
    if return_code in [0, 1]:
        print("[PASS] Check options flag test passed")
        return True
    else:
        print(f"[FAIL] Check options test failed with exit code {return_code}")
        return False


def test_custom_timeout():
    """Test custom timeout value."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--timeout', '10']
    )

    if return_code in [0, 1]:
        print("[PASS] Custom timeout test passed")
        return True
    else:
        print(f"[FAIL] Custom timeout test failed with exit code {return_code}")
        return False


def test_json_has_issues_field():
    """Test JSON output has has_issues boolean field."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'has_issues' not in data:
            print("[FAIL] JSON missing 'has_issues' field")
            return False

        if not isinstance(data['has_issues'], bool):
            print("[FAIL] 'has_issues' should be boolean")
            return False

        print("[PASS] JSON has_issues field test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_has_critical_field():
    """Test JSON output has has_critical boolean field."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'has_critical' not in data:
            print("[FAIL] JSON missing 'has_critical' field")
            return False

        if not isinstance(data['has_critical'], bool):
            print("[FAIL] 'has_critical' should be boolean")
            return False

        print("[PASS] JSON has_critical field test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_verbose_includes_mounts():
    """Test JSON verbose output includes mount details."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)

        if 'mounts' not in data:
            print("[FAIL] JSON verbose missing 'mounts' section")
            return False

        if not isinstance(data['mounts'], list):
            print("[FAIL] 'mounts' should be a list")
            return False

        # Verify mount entry structure if we have any
        if len(data['mounts']) > 0:
            mount = data['mounts'][0]
            required_keys = ['mountpoint', 'device', 'fstype', 'status']
            if not all(key in mount for key in required_keys):
                print("[FAIL] Mount entry missing required keys")
                print(f"  Mount keys: {list(mount.keys())}")
                return False

        print("[PASS] JSON verbose includes mounts test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py']
    )

    # Normal execution should return 0 or 1 (not 2)
    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_format_option_validation():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py', '--format', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Format option validation test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_combined_options():
    """Test multiple options combined."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_mount_health_monitor.py',
         '--format', 'json',
         '--verbose',
         '--skip-virtual',
         '--check-options',
         '--timeout', '3']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Should have both summary and mounts (verbose)
            if 'summary' in data and 'mounts' in data:
                print("[PASS] Combined options test passed")
                return True
            else:
                print("[FAIL] Combined options missing expected fields")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print(f"[FAIL] Combined options test failed with exit code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_mount_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_timeout_low,
        test_invalid_timeout_high,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_skip_virtual_option,
        test_check_options_flag,
        test_custom_timeout,
        test_json_has_issues_field,
        test_json_has_critical_field,
        test_json_verbose_includes_mounts,
        test_exit_codes,
        test_format_option_validation,
        test_combined_options,
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
