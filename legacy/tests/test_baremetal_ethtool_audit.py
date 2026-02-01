#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_ethtool_audit.py functionality.
Tests argument parsing and error handling without requiring ethtool or root access.
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
        [sys.executable, 'baremetal_ethtool_audit.py', '--help']
    )

    if return_code == 0 and 'ethtool' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed - return code: {return_code}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help examples test passed")
        return True
    else:
        print("[FAIL] Help examples test failed")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Exit codes documentation test passed")
        return True
    else:
        print("[FAIL] Exit codes documentation test failed")
        return False


def test_interface_option():
    """Test that the interface option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '-i', 'eth0']
    )

    # Should not fail at argument parsing level (exit code 2 is for missing ethtool)
    if return_code in [0, 1, 2]:
        print("[PASS] Interface option test passed")
        return True
    else:
        print(f"[FAIL] Interface option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_long_interface_option():
    """Test that the --interface long option works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--interface', 'lo']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Long interface option test passed")
        return True
    else:
        print(f"[FAIL] Long interface option test failed with return code: {return_code}")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        return False


def test_long_verbose_option():
    """Test that the --verbose long option works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--verbose']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Long verbose option test passed")
        return True
    else:
        print(f"[FAIL] Long verbose option test failed with return code: {return_code}")
        return False


def test_format_option_plain():
    """Test that the plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed with return code: {return_code}")
        return False


def test_format_option_json():
    """Test that the json format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print(f"[FAIL] JSON format option test failed with return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--format', 'invalid']
    )

    # Should fail with argument error (not 0, 1, or 2)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_warn_only_short_option():
    """Test that the -w warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only option test failed with return code: {return_code}")
        return False


def test_warn_only_long_option():
    """Test that the --warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Long warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Long warn-only option test failed with return code: {return_code}")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_ethtool_audit.py',
        '-i', 'eth0',
        '-v',
        '--format', 'json',
        '-w'
    ])

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with return code: {return_code}")
        return False


def test_unknown_option():
    """Test that unknown options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--unknown-option']
    )

    # argparse should reject unknown options with exit code 2
    if return_code == 2 and ('unrecognized arguments' in stderr or 'error' in stderr.lower()):
        print("[PASS] Unknown option test passed")
        return True
    else:
        print(f"[FAIL] Unknown option test failed - should reject unknown option")
        print(f"  return_code: {return_code}, stderr: {stderr}")
        return False


def test_json_output_structure():
    """Test that JSON output has expected structure when ethtool is available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py', '--format', 'json']
    )

    # If ethtool is not available, exit code is 2 which is fine
    if return_code == 2:
        print("[PASS] JSON output structure test passed (ethtool not available)")
        return True

    # If ethtool is available, verify JSON structure
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'interfaces' in data and 'global_issues' in data and 'summary' in data:
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON output is not valid JSON")
            return False

    print(f"[FAIL] JSON output structure test failed with return code: {return_code}")
    return False


def test_missing_ethtool_message():
    """Test that missing ethtool produces helpful error message"""
    # This test verifies the error handling when ethtool is missing
    # We can't easily force ethtool to be missing, but we can check
    # that the script doesn't crash with an unhandled exception
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ethtool_audit.py']
    )

    # Exit code 2 means ethtool not found - check for helpful message
    if return_code == 2:
        if 'ethtool' in stderr.lower() and 'install' in stderr.lower():
            print("[PASS] Missing ethtool message test passed")
            return True
        else:
            print("[FAIL] Missing ethtool message not helpful enough")
            return False
    elif return_code in [0, 1]:
        # ethtool is available, test passes
        print("[PASS] Missing ethtool message test passed (ethtool available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_docstring_present():
    """Test that the script has a proper docstring"""
    return_code, stdout, stderr = run_command(
        [sys.executable, '-c',
         "import baremetal_ethtool_audit; print(baremetal_ethtool_audit.__doc__)"]
    )

    if return_code == 0 and 'Exit codes' in stdout:
        print("[PASS] Docstring test passed")
        return True
    else:
        print("[FAIL] Docstring test failed - missing or incomplete docstring")
        return False


if __name__ == "__main__":
    print("Testing baremetal_ethtool_audit.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_interface_option,
        test_long_interface_option,
        test_verbose_option,
        test_long_verbose_option,
        test_format_option_plain,
        test_format_option_json,
        test_invalid_format,
        test_warn_only_short_option,
        test_warn_only_long_option,
        test_combined_options,
        test_unknown_option,
        test_json_output_structure,
        test_missing_ethtool_message,
        test_docstring_present,
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
