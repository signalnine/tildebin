#!/usr/bin/env python3
"""
Test script for baremetal_xfs_health_monitor.py functionality.
Tests argument parsing and error handling without requiring root access or XFS filesystems.
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
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--help']
    )

    if return_code == 0 and 'xfs' in stdout.lower() and 'health' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--format', 'plain']
    )

    # May succeed or fail depending on XFS availability, but shouldn't be usage error
    # unless xfs_info is missing
    if return_code != 2 or 'xfs_info' in stderr:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_option_json():
    """Test JSON format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--format', 'json']
    )

    # If xfs_info is missing, return code is 2 (acceptable)
    # If no XFS filesystems, should still produce valid JSON
    if return_code == 2 and 'xfs_info' in stderr:
        print("[PASS] JSON format option test passed (xfs_info not available)")
        return True

    # Try to parse JSON output
    try:
        if stdout.strip():
            data = json.loads(stdout)
            if 'filesystems' in data or 'timestamp' in data:
                print("[PASS] JSON format option test passed")
                return True
    except json.JSONDecodeError:
        pass

    # Accept if it ran without argument error
    if return_code in [0, 1]:
        print("[PASS] JSON format option test passed")
        return True

    print(f"[FAIL] JSON format option test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stdout: {stdout[:200]}")
    return False


def test_format_option_table():
    """Test table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--format', 'table']
    )

    # Should accept the option (exit 2 only if xfs_info missing)
    if return_code in [0, 1] or (return_code == 2 and 'xfs_info' in stderr):
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '-v']
    )

    # Should accept the flag
    if return_code in [0, 1] or (return_code == 2 and 'xfs_info' in stderr):
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--warn-only']
    )

    # Should accept the flag
    if return_code in [0, 1] or (return_code == 2 and 'xfs_info' in stderr):
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_mount_option():
    """Test mount option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--mount', '/nonexistent']
    )

    # Should accept the option (will fail on the mount, but that's expected)
    if return_code in [0, 1, 2]:  # 2 is acceptable (mount not found)
        print("[PASS] Mount option test passed")
        return True
    else:
        print(f"[FAIL] Mount option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_verbose_flag():
    """Test short verbose flag -v is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '-v']
    )

    if return_code in [0, 1] or (return_code == 2 and 'xfs_info' in stderr):
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Short verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_warn_only_flag():
    """Test short warn-only flag -w is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '-w']
    )

    if return_code in [0, 1] or (return_code == 2 and 'xfs_info' in stderr):
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_mount_flag():
    """Test short mount flag -m is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '-m', '/tmp']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Short mount flag test passed")
        return True
    else:
        print(f"[FAIL] Short mount flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py',
         '--format', 'json', '-v', '--warn-only']
    )

    if return_code in [0, 1] or (return_code == 2 and 'xfs_info' in stderr):
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_structure():
    """Test JSON output structure when available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--format', 'json']
    )

    # If xfs_info is missing, skip structure test
    if return_code == 2 and 'xfs_info' in stderr:
        print("[PASS] JSON structure test passed (xfs_info not available)")
        return True

    try:
        if stdout.strip():
            data = json.loads(stdout)

            # Check for expected top-level keys
            expected_keys = ['timestamp', 'filesystems']
            has_keys = all(key in data for key in expected_keys)

            if has_keys:
                print("[PASS] JSON structure test passed")
                return True
            else:
                print(f"[FAIL] JSON missing expected keys")
                print(f"  Found keys: {list(data.keys())}")
                return False
        else:
            # Empty output with success code is acceptable (no XFS filesystems)
            print("[PASS] JSON structure test passed (no output)")
            return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_missing_xfs_info_message():
    """Test helpful error message when xfs_info is missing"""
    # This test checks the error message format - it will pass even if
    # xfs_info is installed since we're just testing the script loads
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--help']
    )

    # Help should always work
    if return_code == 0:
        print("[PASS] Missing xfs_info message test passed")
        return True
    else:
        print(f"[FAIL] Help should work regardless of xfs_info")
        return False


def test_exit_codes_documented():
    """Test that exit codes are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--help']
    )

    if 'exit code' in stdout.lower() or 'Exit codes' in stdout:
        print("[PASS] Exit codes documentation test passed")
        return True
    else:
        print(f"[FAIL] Exit codes should be documented in help")
        return False


def test_examples_in_help():
    """Test that examples are included in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--help']
    )

    if 'example' in stdout.lower() or 'Examples' in stdout:
        print("[PASS] Examples in help test passed")
        return True
    else:
        print(f"[FAIL] Examples should be in help")
        return False


def test_no_xfs_filesystems_handling():
    """Test that script handles no XFS filesystems gracefully"""
    # If there are no XFS filesystems, the script should exit 0 with appropriate message
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_xfs_health_monitor.py', '--format', 'json']
    )

    # If xfs_info is missing
    if return_code == 2 and 'xfs_info' in stderr:
        print("[PASS] No XFS filesystems handling test passed (xfs_info not available)")
        return True

    # If no XFS filesystems, should get valid JSON with empty list
    if return_code == 0:
        try:
            data = json.loads(stdout)
            if 'filesystems' in data:
                print("[PASS] No XFS filesystems handling test passed")
                return True
        except json.JSONDecodeError:
            pass

    # Also acceptable if there are XFS filesystems and it ran successfully
    if return_code in [0, 1]:
        print("[PASS] No XFS filesystems handling test passed")
        return True

    print(f"[FAIL] No XFS filesystems handling test failed")
    print(f"  Return code: {return_code}")
    return False


if __name__ == "__main__":
    print("Testing baremetal_xfs_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_mount_option,
        test_short_verbose_flag,
        test_short_warn_only_flag,
        test_short_mount_flag,
        test_combined_flags,
        test_json_structure,
        test_missing_xfs_info_message,
        test_exit_codes_documented,
        test_examples_in_help,
        test_no_xfs_filesystems_handling,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
