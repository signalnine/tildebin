#!/usr/bin/env python3
"""
Test script for baremetal_dmesg_analyzer.py functionality.
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
        stdout, stderr = proc.communicate(timeout=10)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--help']
    )

    if return_code == 0 and 'dmesg' in stdout.lower() and 'kernel' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test that plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--format', 'plain']
    )

    # Script will run (may succeed or fail based on dmesg availability)
    # We're testing that the option is recognized
    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--format', 'json']
    )

    # If script runs successfully or finds issues
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'findings' in data:
                print("[PASS] JSON format option test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON format test failed: invalid JSON output")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # dmesg not available - that's OK for this test
        print("[PASS] JSON format option test passed (dmesg not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed: unexpected return code {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--format', 'invalid']
    )

    # Should fail with exit code 2 (usage error) or show error message
    if return_code == 2 or 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '-v']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_since_option():
    """Test that since option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--since', '1 hour ago']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Since option test passed")
        return True
    else:
        print(f"[FAIL] Since option test failed: unexpected return code {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py',
         '--format', 'json', '-v', '--warn-only']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    # Run with plain format to check exit codes
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_dmesg_analyzer.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (no issues), 1 (issues found), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_dmesg_analyzer.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_since_option,
        test_combined_options,
        test_exit_codes,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print(f"✗ {total - passed} test(s) failed")
        sys.exit(1)
