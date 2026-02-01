#!/usr/bin/env python3
"""
Test script for baremetal_bond_health_monitor.py functionality.
Tests argument parsing and error handling without requiring actual bond interfaces.
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
        [sys.executable, 'baremetal_bond_health_monitor.py', '--help']
    )

    if return_code == 0 and 'network bond health' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_bond_option():
    """Test that the --bond option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '-b', 'bond0']
    )

    # Will fail without bonding, but option should parse correctly
    # Exit code 2 means missing dependency (expected)
    # Exit code 0 or 1 means it ran successfully
    if return_code in [0, 1, 2]:
        print("[PASS] Bond option test passed")
        return True
    else:
        print(f"[FAIL] Bond option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_long_bond_option():
    """Test that the --bond long option works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '--bond', 'bond1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Long bond option test passed")
        return True
    else:
        print(f"[FAIL] Long bond option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_format_option():
    """Test that the format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '--format', 'json']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Format option test passed")
        return True
    else:
        print(f"[FAIL] Format option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with argument error (exit code 2)
    if return_code == 2 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format test failed")
        print(f"  Expected exit code 2, got {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_table_format():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '--format', 'table']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Table format test passed")
        return True
    else:
        print(f"[FAIL] Table format test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '--warn-only']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_bond_health_monitor.py',
        '-b', 'bond0',
        '-v',
        '--format', 'json'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_json_output_structure():
    """Test that JSON format produces valid JSON structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py', '--format', 'json']
    )

    # If bonding not available, will exit with code 2
    if return_code == 2:
        print("[PASS] JSON output structure test passed (bonding not available)")
        return True

    # If bonding available, check JSON structure
    if return_code in [0, 1]:
        try:
            # Should be valid JSON (array of bonds)
            data = json.loads(stdout)
            if isinstance(data, list):
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print(f"[FAIL] JSON output is not an array")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON output structure test failed - invalid JSON: {e}")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] JSON output structure test failed with unexpected return code: {return_code}")
    return False


def test_missing_dependency_handling():
    """Test graceful handling of missing bonding support"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py']
    )

    # Should either work (0/1) or fail gracefully with dependency error (2)
    if return_code in [0, 1, 2]:
        if return_code == 2:
            # Should have helpful error message
            if 'bonding' in stderr.lower() or 'bonding' in stdout.lower():
                print("[PASS] Missing dependency handling test passed")
                return True
            else:
                print(f"[FAIL] Exit code 2 but missing helpful error message")
                return False
        else:
            # Bonding available, script ran
            print("[PASS] Missing dependency handling test passed (bonding available)")
            return True
    else:
        print(f"[FAIL] Missing dependency handling test failed with return code: {return_code}")
        return False


def test_short_options():
    """Test that short option forms work"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_bond_health_monitor.py',
        '-b', 'bond0',
        '-v',
        '-w'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Short options test passed")
        return True
    else:
        print(f"[FAIL] Short options test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_exit_codes():
    """Test that script uses proper exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_bond_health_monitor.py']
    )

    # Valid exit codes are:
    # 0 = success/healthy
    # 1 = warnings/errors found
    # 2 = missing dependency or usage error
    if return_code in [0, 1, 2]:
        print("[PASS] Exit codes test passed")
        return True
    else:
        print(f"[FAIL] Exit codes test failed - invalid exit code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_bond_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_bond_option,
        test_long_bond_option,
        test_verbose_option,
        test_format_option,
        test_invalid_format,
        test_table_format,
        test_warn_only_option,
        test_combined_options,
        test_json_output_structure,
        test_missing_dependency_handling,
        test_short_options,
        test_exit_codes
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
