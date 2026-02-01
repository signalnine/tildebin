#!/usr/bin/env python3
"""
Test script for baremetal_inode_usage_monitor.py functionality.
Tests argument parsing and error handling without requiring special permissions.
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
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--help']
    )

    if return_code == 0 and 'inode' in stdout.lower() and 'usage' in stdout.lower():
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
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--format', 'plain']
    )

    # Should succeed (system always has some filesystems)
    if return_code in [0, 1]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_option_json():
    """Test JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON format option test failed - unexpected return code")
        print(f"  Return code: {return_code}")
        return False

    try:
        data = json.loads(stdout)
        if 'filesystems' in data and 'timestamp' in data:
            print("[PASS] JSON format option test passed")
            return True
        else:
            print(f"[FAIL] JSON missing expected keys")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_table():
    """Test table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_inode_usage_monitor.py', '-v']
    )

    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--warn-only']
    )

    if return_code in [0, 1]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_threshold_option():
    """Test custom warning threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--warn-threshold', '70']
    )

    if return_code in [0, 1]:
        print("[PASS] Warn threshold option test passed")
        return True
    else:
        print(f"[FAIL] Warn threshold option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_critical_threshold_option():
    """Test custom critical threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--critical-threshold', '90']
    )

    if return_code in [0, 1]:
        print("[PASS] Critical threshold option test passed")
        return True
    else:
        print(f"[FAIL] Critical threshold option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_order():
    """Test that warning >= critical threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py',
         '--warn-threshold', '95', '--critical-threshold', '90']
    )

    if return_code == 2 and 'less than' in stderr.lower():
        print("[PASS] Invalid threshold order test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold order should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_mount_option():
    """Test mount point filtering option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '-m', '/']
    )

    # Should work for root mount point
    if return_code in [0, 1]:
        print("[PASS] Mount option test passed")
        return True
    else:
        print(f"[FAIL] Mount option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_mount():
    """Test that invalid mount point is handled"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '-m', '/nonexistent']
    )

    if return_code == 2 and 'not found' in stderr.lower():
        print("[PASS] Invalid mount test passed")
        return True
    else:
        print(f"[FAIL] Invalid mount should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py',
         '--format', 'json', '-v', '--warn-only']
    )

    if return_code in [0, 1]:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--format', 'json']
    )

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON structure test failed - bad return code")
        return False

    try:
        data = json.loads(stdout)

        # Check top-level keys
        required_keys = ['timestamp', 'filesystems', 'summary']
        has_keys = all(key in data for key in required_keys)

        if not has_keys:
            print(f"[FAIL] JSON missing required keys")
            print(f"  Found: {list(data.keys())}")
            return False

        # Check summary structure
        summary_keys = ['total', 'healthy', 'warning', 'critical']
        has_summary = all(key in data['summary'] for key in summary_keys)

        if not has_summary:
            print(f"[FAIL] JSON summary missing keys")
            return False

        # Check filesystem structure if any exist
        if data['filesystems']:
            fs = data['filesystems'][0]
            fs_keys = ['mount_point', 'device', 'inodes_total', 'inodes_used', 'use_percent', 'status']
            has_fs_keys = all(key in fs for key in fs_keys)
            if not has_fs_keys:
                print(f"[FAIL] Filesystem entry missing keys")
                print(f"  Found: {list(fs.keys())}")
                return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_codes_documented():
    """Test that exit codes are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--help']
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
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--help']
    )

    if 'example' in stdout.lower() or 'Examples' in stdout:
        print("[PASS] Examples in help test passed")
        return True
    else:
        print(f"[FAIL] Examples should be in help")
        return False


def test_threshold_validation():
    """Test threshold values are validated"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--warn-threshold', '150']
    )

    if return_code == 2 and 'between' in stderr.lower():
        print("[PASS] Threshold validation test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_output_contains_filesystem_info():
    """Test that output contains filesystem information"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py']
    )

    # Should have at least root filesystem
    if return_code in [0, 1] and ('/' in stdout or 'inode' in stdout.lower()):
        print("[PASS] Output contains filesystem info test passed")
        return True
    else:
        print(f"[FAIL] Output should contain filesystem info")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_format_headers():
    """Test table format has proper headers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_inode_usage_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Check for header elements
        if 'Mount Point' in stdout or 'Inodes' in stdout or 'No inode' in stdout:
            print("[PASS] Table format headers test passed")
            return True

    print(f"[FAIL] Table format should have headers")
    print(f"  Output: {stdout[:200]}")
    return False


if __name__ == "__main__":
    print("Testing baremetal_inode_usage_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_warn_threshold_option,
        test_critical_threshold_option,
        test_invalid_threshold_order,
        test_mount_option,
        test_invalid_mount,
        test_combined_flags,
        test_json_structure,
        test_exit_codes_documented,
        test_examples_in_help,
        test_threshold_validation,
        test_output_contains_filesystem_info,
        test_table_format_headers,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
