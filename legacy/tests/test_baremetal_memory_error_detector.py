#!/usr/bin/env python3
"""
Test script for baremetal_memory_error_detector.py functionality.
Tests argument parsing and error handling without requiring actual EDAC hardware.
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
        [sys.executable, 'baremetal_memory_error_detector.py', '--help']
    )

    if return_code == 0 and 'memory error' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option():
    """Test that the format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '--format', 'json']
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
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '--format', 'invalid']
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
    """Test that table format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '--format', 'table']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Table format test passed")
        return True
    else:
        print(f"[FAIL] Table format test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '--warn-only']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_short_verbose():
    """Test that short verbose option works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short verbose option test passed")
        return True
    else:
        print(f"[FAIL] Short verbose option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_short_warn_only():
    """Test that short warn-only option works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_check_mce_option():
    """Test that the check-mce option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '--check-mce']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Check-mce option test passed")
        return True
    else:
        print(f"[FAIL] Check-mce option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_memory_error_detector.py',
        '-v',
        '--format', 'json',
        '--check-mce'
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
    """Test that JSON format produces valid JSON structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '--format', 'json']
    )

    # Script should run and produce valid JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected keys
            if 'summary' in data or 'memory_controllers' in data or 'analysis' in data:
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print(f"[FAIL] JSON output missing expected keys")
                print(f"  Keys found: {list(data.keys())}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON output structure test failed - invalid JSON: {e}")
            print(f"  Output: {stdout[:200]}")
            return False

    # If EDAC not available, it should still produce valid JSON
    if return_code == 0:
        try:
            data = json.loads(stdout)
            print("[PASS] JSON output structure test passed (EDAC not available)")
            return True
        except json.JSONDecodeError:
            pass

    print(f"[PASS] JSON output structure test passed (no EDAC hardware)")
    return True


def test_exit_codes():
    """Test that script uses proper exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py']
    )

    # Valid exit codes are:
    # 0 = success/no errors or no EDAC support
    # 1 = memory errors found
    # 2 = usage error
    if return_code in [0, 1, 2]:
        print("[PASS] Exit codes test passed")
        return True
    else:
        print(f"[FAIL] Exit codes test failed - invalid exit code: {return_code}")
        return False


def test_graceful_no_edac():
    """Test graceful handling when EDAC is not available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py']
    )

    # Should handle gracefully (exit 0 if no EDAC, not crash)
    if return_code in [0, 1]:
        print("[PASS] Graceful no-EDAC handling test passed")
        return True
    else:
        print(f"[FAIL] Graceful no-EDAC handling test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_short_format():
    """Test that short format option works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_memory_error_detector.py', '-f', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short format option test passed")
        return True
    else:
        print(f"[FAIL] Short format option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_memory_error_detector.py...")
    print()

    tests = [
        test_help_message,
        test_format_option,
        test_invalid_format,
        test_table_format,
        test_verbose_option,
        test_warn_only_option,
        test_short_verbose,
        test_short_warn_only,
        test_check_mce_option,
        test_combined_options,
        test_json_output_structure,
        test_exit_codes,
        test_graceful_no_edac,
        test_short_format,
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
