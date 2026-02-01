#!/usr/bin/env python3
"""
Test script for baremetal_filesystem_readonly_monitor.py functionality.
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
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py', '--help']
    )

    if return_code == 0 and 'Monitor filesystems' in stdout and 'read-only' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_plain_output():
    """Test default plain output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py']
    )

    # Should succeed (exit 0 or 1) and produce output
    if return_code in [0, 1] and (stdout.strip() or 'Error' in stderr):
        print("[PASS] Plain output test passed")
        return True
    else:
        print(f"[FAIL] Plain output test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stdout: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Verify expected fields
        if 'filesystems' in data and 'timestamp' in data and 'readonly_count' in data:
            print("[PASS] JSON output format test passed")
            return True
        else:
            print(f"[FAIL] JSON missing expected fields")
            print(f"  Keys: {list(data.keys())}")
            return False

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py', '--format', 'table']
    )

    # Should succeed and produce output
    if return_code in [0, 1]:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_flag():
    """Test verbose flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py', '-v']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py', '--warn-only']
    )

    # Should succeed (may have no output if no warnings)
    if return_code in [0, 1]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_structure():
    """Test JSON output structure in detail"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Check required fields
        required_fields = ['filesystems', 'kernel_errors', 'readonly_count', 'total_count', 'timestamp']
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            print(f"[FAIL] JSON structure missing fields: {missing_fields}")
            return False

        # Check filesystems is a list
        if not isinstance(data['filesystems'], list):
            print(f"[FAIL] 'filesystems' should be a list")
            return False

        # If there are filesystems, check their structure
        if data['filesystems']:
            fs = data['filesystems'][0]
            required_fs_fields = ['device', 'mount_point', 'fs_type', 'readonly']
            missing_fs_fields = [field for field in required_fs_fields if field not in fs]

            if missing_fs_fields:
                print(f"[FAIL] Filesystem entry missing fields: {missing_fs_fields}")
                return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_filesystem_readonly_monitor.py',
         '--format', 'json', '-v', '--warn-only']
    )

    # Should work with combined flags
    if return_code in [0, 1]:
        try:
            json.loads(stdout)
            print("[PASS] Combined flags test passed")
            return True
        except json.JSONDecodeError:
            print(f"[FAIL] Combined flags produced invalid JSON")
            return False
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_filesystem_readonly_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_plain_output,
        test_json_output_format,
        test_table_output_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_invalid_format,
        test_json_structure,
        test_combined_flags,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
