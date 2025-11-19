#!/usr/bin/env python3
"""
Test script for kernel_module_audit.py functionality.
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
        [sys.executable, 'kernel_module_audit.py', '--help']
    )

    if return_code == 0 and 'kernel modules' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_argument():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid argument test passed")
        return True
    else:
        print("[FAIL] Invalid argument should fail")
        return False


def test_format_plain():
    """Test plain format output"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--format', 'plain']
    )

    # Should work on any Linux system with /proc/modules
    if 'modules' in stdout.lower() or 'Module Audit' in stdout:
        print("[PASS] Plain format test passed")
        return True
    else:
        print(f"[FAIL] Plain format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_json():
    """Test JSON format output parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        if 'summary' in data:
            print("[PASS] JSON format test passed")
            return True
        else:
            print("[FAIL] JSON format missing expected keys")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_table():
    """Test table format output"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--format', 'table']
    )

    if 'Metric' in stdout or 'Total Modules' in stdout or '-' * 10 in stdout:
        print("[PASS] Table format test passed")
        return True
    else:
        print(f"[FAIL] Table format test failed")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_flag():
    """Test --warn-only flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--warn-only']
    )

    # Should complete successfully (may or may not have issues)
    if return_code in [0, 1]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_verbose_flag():
    """Test --verbose flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--verbose']
    )

    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed with code {return_code}")
        return False


def test_no_unknown_check_flag():
    """Test --no-unknown-check flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--no-unknown-check']
    )

    if return_code in [0, 1]:
        print("[PASS] No-unknown-check flag test passed")
        return True
    else:
        print(f"[FAIL] No-unknown-check flag test failed")
        return False


def test_json_structure():
    """Test that JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Check for required fields
        required_summary_fields = [
            'total_modules', 'known_modules', 'unknown_modules', 'tainted_modules'
        ]

        for field in required_summary_fields:
            if field not in data.get('summary', {}):
                print(f"[FAIL] JSON missing summary field: {field}")
                return False

        if 'issues' not in data:
            print("[FAIL] JSON missing 'issues' field")
            return False

        print("[PASS] JSON structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON structure test failed: {e}")
        return False


def test_combined_flags():
    """Test multiple flags combined"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py', '--format', 'json', '--warn-only']
    )

    try:
        data = json.loads(stdout)
        # When warn-only, modules list should not be included
        print("[PASS] Combined flags test passed")
        return True
    except json.JSONDecodeError:
        print("[FAIL] Combined flags test failed")
        return False


def test_exit_codes():
    """Test that exit codes are valid (0 or 1)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'kernel_module_audit.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: got {return_code}")
        return False


if __name__ == "__main__":
    print("Testing kernel_module_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_argument,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_warn_only_flag,
        test_verbose_flag,
        test_no_unknown_check_flag,
        test_json_structure,
        test_combined_flags,
        test_exit_codes,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
