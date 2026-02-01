#!/usr/bin/env python3
"""
Test script for baremetal_user_login_audit.py functionality.
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
        [sys.executable, 'baremetal_user_login_audit.py', '--help']
    )

    if return_code == 0 and 'user accounts' in stdout.lower():
        if 'dormant' in stdout.lower() and 'login' in stdout.lower():
            print("[PASS] Help message test passed")
            return True

    print(f"[FAIL] Help message test failed")
    print(f"  Return code: {return_code}")
    print(f"  Output: {stdout[:200]}")
    return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_parsing():
    """Test that format options are recognized"""
    test_cases = [
        (['--format', 'json'], 'json format'),
        (['--format', 'table'], 'table format'),
        (['--format', 'plain'], 'plain format'),
    ]

    for args, desc in test_cases:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_user_login_audit.py'] + args
        )

        # Exit code 2 means lastlog missing, which may happen
        # Exit codes 0 or 1 are both valid (0=no issues, 1=issues found)
        if return_code in [0, 1, 2]:
            continue
        else:
            print(f"[FAIL] Format option test failed for {desc}")
            print(f"  Return code: {return_code}")
            print(f"  Stderr: {stderr[:200]}")
            return False

    print("[PASS] Format option parsing test passed")
    return True


def test_dormant_days_option():
    """Test that dormant-days option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '--dormant-days', '30']
    )

    # Exit code 2 means dependency missing, 0/1 are valid
    if return_code in [0, 1, 2]:
        print("[PASS] Dormant-days option test passed")
        return True
    else:
        print(f"[FAIL] Dormant-days option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_min_uid_option():
    """Test that min-uid option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '--min-uid', '500']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Min-uid option test passed")
        return True
    else:
        print(f"[FAIL] Min-uid option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_include_system_flag():
    """Test that --include-system flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '--include-system']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Include-system flag test passed")
        return True
    else:
        print(f"[FAIL] Include-system flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test that --warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_flag():
    """Test that --verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_output_format():
    """Test that JSON output is valid when lastlog is available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '--format', 'json']
    )

    # If lastlog is not available, exit code 2 is acceptable
    if return_code == 2:
        if 'lastlog' in stderr.lower():
            print("[PASS] JSON output format test passed (lastlog unavailable)")
            return True

    # If it ran successfully, validate JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'users' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON parsing failed")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] JSON output format test failed")
    print(f"  Return code: {return_code}")
    return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py',
         '--dormant-days', '60',
         '--min-uid', '1000',
         '--format', 'json',
         '--warn-only']
    )

    # Exit code 2 means dependency missing
    if return_code == 2:
        print("[PASS] Combined options test passed (lastlog unavailable)")
        return True

    # If it ran, validate JSON output
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data:
                print("[PASS] Combined options test passed")
                return True
        except json.JSONDecodeError:
            pass

    print(f"[FAIL] Combined options test failed")
    print(f"  Return code: {return_code}")
    return False


def test_invalid_dormant_days():
    """Test that invalid dormant-days value is handled"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_user_login_audit.py',
         '--dormant-days', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid dormant-days value test passed")
        return True
    else:
        print("[FAIL] Invalid dormant-days should fail")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_user_login_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_parsing,
        test_dormant_days_option,
        test_min_uid_option,
        test_include_system_flag,
        test_warn_only_flag,
        test_verbose_flag,
        test_json_output_format,
        test_invalid_format_option,
        test_combined_options,
        test_invalid_dormant_days,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"Failed: {total - passed} test(s)")
        sys.exit(1)
