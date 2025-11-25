#!/usr/bin/env python3
"""
Test script for baremetal_network_config_audit.py functionality.
Tests argument parsing and error handling without requiring specific network configuration.
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
        [sys.executable, 'baremetal_network_config_audit.py', '--help']
    )

    if return_code == 0 and 'network interface' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py', '--invalid-flag']
    )

    # Should fail with exit code 2 (usage error)
    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py']
    )

    # Should succeed (exit 0 or 1), output should be plain text
    if return_code in [0, 1]:
        # Check it's not JSON
        try:
            json.loads(stdout)
            print("[FAIL] Plain output should not be JSON")
            return False
        except json.JSONDecodeError:
            # Good, it's not JSON
            print("[PASS] Plain output format test passed")
            return True
    else:
        print(f"[FAIL] Plain output test failed with return code {return_code}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py', '--format', 'json']
    )

    # Should succeed (exit 0 or 1)
    if return_code not in [0, 1]:
        print(f"[FAIL] JSON format test failed with return code {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False

    # Try to parse JSON output
    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            print("[PASS] JSON output format test passed")
            return True
        else:
            print(f"[FAIL] JSON output is not a list")
            return False
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py', '--format', 'table']
    )

    # Should succeed (exit 0 or 1)
    if return_code not in [0, 1]:
        print(f"[FAIL] Table format test failed with return code {return_code}")
        return False

    # Table format should have header with "Severity" or "Category"
    if 'Severity' in stdout or 'Category' in stdout or 'No issues' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table format doesn't look correct")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_flag():
    """Test verbose flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py', '--verbose']
    )

    # Should succeed (exit 0 or 1)
    if return_code in [0, 1]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed with return code {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py', '--warn-only']
    )

    # Should succeed (exit 0 or 1)
    if return_code in [0, 1]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with return code {return_code}")
        return False


def test_combined_flags():
    """Test combination of flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py',
         '--format', 'json', '--verbose', '--warn-only']
    )

    # Should succeed and output valid JSON
    if return_code not in [0, 1]:
        print(f"[FAIL] Combined flags test failed with return code {return_code}")
        return False

    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            print("[PASS] Combined flags test passed")
            return True
        else:
            print(f"[FAIL] Combined flags JSON output is not a list")
            return False
    except json.JSONDecodeError:
        print(f"[FAIL] Combined flags JSON parsing failed")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py', '--format', 'xml']
    )

    # Should fail with usage error
    if return_code != 0:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_exit_codes():
    """Test that exit codes are appropriate"""
    # Run normally - should exit 0 or 1
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_config_audit.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Expected exit code 0 or 1, got {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_network_config_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_flags,
        test_invalid_format,
        test_exit_codes,
    ]

    passed = 0
    failed = 0

    for test in tests:
        if test():
            passed += 1
        else:
            failed += 1
        print()

    total = len(tests)
    print(f"Test Results: {passed}/{total} tests passed")

    if failed > 0:
        print(f"  {failed} test(s) failed")
        sys.exit(1)
    else:
        print("  All tests passed!")
        sys.exit(0)
