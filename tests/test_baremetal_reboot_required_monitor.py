#!/usr/bin/env python3
"""
Test script for baremetal_reboot_required_monitor.py functionality.
Tests argument parsing and output formats without requiring root privileges
or specific system state.
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
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--help']
    )

    if return_code == 0 and 'reboot' in stdout.lower():
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
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_reboot_required_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on system state)
    if return_code in [0, 1] and 'Status:' in stdout:
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
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['status', 'reboot_required', 'reboot_recommended',
                        'kernel', 'issues']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify kernel data structure
        kernel = data['kernel']
        if 'running' not in kernel or 'mismatch' not in kernel:
            print("[FAIL] JSON kernel data missing required keys")
            print(f"  Kernel keys: {list(kernel.keys())}")
            return False

        # Verify status is one of expected values
        valid_statuses = ['OK', 'REBOOT_REQUIRED', 'REBOOT_RECOMMENDED']
        if data['status'] not in valid_statuses:
            print(f"[FAIL] Invalid status: {data['status']}")
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
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'REBOOT STATUS' in stdout:
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
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--verbose']
    )

    # Should succeed and include kernel info
    if return_code in [0, 1] and 'kernel' in stdout.lower():
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        # In warn-only mode with no reboot needed, output should be minimal/empty
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_reboot_required_monitor.py']
    )

    # Exit code should be 0 (no reboot) or 1 (reboot needed), never 2 for normal runs
    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_issues_array():
    """Test that JSON output contains issues as an array."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        if 'issues' not in data:
            print("[FAIL] JSON output missing 'issues' key")
            return False

        if not isinstance(data['issues'], list):
            print("[FAIL] JSON 'issues' should be an array")
            return False

        # Verify issue structure if there are any issues
        for issue in data['issues']:
            required_fields = ['severity', 'message', 'category']
            if not all(field in issue for field in required_fields):
                print("[FAIL] Issue missing required fields")
                print(f"  Issue keys: {list(issue.keys())}")
                return False

        print("[PASS] JSON issues array test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_format_option_values():
    """Test all valid format option values."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_reboot_required_monitor.py', '--format', fmt]
        )

        if return_code not in [0, 1]:
            print(f"[FAIL] Format '{fmt}' returned error code {return_code}")
            return False

    print("[PASS] All format options test passed")
    return True


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_reboot_required_monitor.py',
         '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)
        if return_code in [0, 1] and 'kernel' in data:
            print("[PASS] Combined options test passed")
            return True
        else:
            print(f"[FAIL] Combined options test failed")
            return False
    except json.JSONDecodeError:
        print("[FAIL] Combined options JSON parsing failed")
        return False


def test_json_kernel_structure():
    """Test JSON kernel structure has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        kernel = data.get('kernel', {})

        expected_keys = ['running', 'mismatch', 'newest_installed', 'available_kernels']
        for key in expected_keys:
            if key not in kernel:
                print(f"[FAIL] Kernel missing key: {key}")
                return False

        # running should be a string
        if not isinstance(kernel['running'], str):
            print("[FAIL] kernel.running should be a string")
            return False

        # mismatch should be a boolean
        if not isinstance(kernel['mismatch'], bool):
            print("[FAIL] kernel.mismatch should be a boolean")
            return False

        # available_kernels should be a list
        if not isinstance(kernel['available_kernels'], list):
            print("[FAIL] kernel.available_kernels should be a list")
            return False

        print("[PASS] JSON kernel structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_json_boolean_fields():
    """Test JSON boolean fields are actual booleans."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_reboot_required_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)

        # Check reboot_required and reboot_recommended are booleans
        if not isinstance(data.get('reboot_required'), bool):
            print("[FAIL] reboot_required should be a boolean")
            return False

        if not isinstance(data.get('reboot_recommended'), bool):
            print("[FAIL] reboot_recommended should be a boolean")
            return False

        print("[PASS] JSON boolean fields test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_script_metadata():
    """Test script has proper shebang and docstring."""
    try:
        with open('baremetal_reboot_required_monitor.py', 'r') as f:
            content = f.read()

        # Check shebang
        if not content.startswith('#!/usr/bin/env python3'):
            print("[FAIL] Script missing proper shebang")
            return False

        # Check for docstring with exit codes
        if 'Exit codes:' not in content:
            print("[FAIL] Script missing exit codes documentation")
            return False

        # Check for argparse import
        if 'import argparse' not in content:
            print("[FAIL] Script missing argparse import")
            return False

        print("[PASS] Script metadata test passed")
        return True
    except FileNotFoundError:
        print("[FAIL] Script file not found")
        return False


if __name__ == "__main__":
    print("Testing baremetal_reboot_required_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_exit_codes,
        test_json_issues_array,
        test_format_option_values,
        test_combined_options,
        test_json_kernel_structure,
        test_json_boolean_fields,
        test_script_metadata,
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
