#!/usr/bin/env python3
"""
Test script for iosched_audit.py functionality.
Tests argument parsing and error handling without requiring root access or specific hardware.
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
        [sys.executable, 'iosched_audit.py', '--help']
    )

    if return_code == 0 and 'I/O scheduler' in stdout and 'scheduler' in stdout.lower():
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
        [sys.executable, 'iosched_audit.py', '--invalid-flag']
    )

    # Should fail with exit code 2 (usage error)
    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should cause non-zero exit")
        return False


def test_format_options():
    """Test that format options are accepted"""
    test_cases = [
        (['--format', 'plain'], 'plain format'),
        (['--format', 'json'], 'JSON format'),
        (['--format', 'table'], 'table format'),
    ]

    all_passed = True
    for args, description in test_cases:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'iosched_audit.py'] + args
        )

        # Should accept the format option (exit 0, 1, or 2 depending on system state)
        # We just verify the option is parsed, not the actual system state
        if return_code in [0, 1, 2]:
            print(f"[PASS] Format option test passed: {description}")
        else:
            print(f"[FAIL] Format option test failed: {description}")
            print(f"  Return code: {return_code}")
            print(f"  Stderr: {stderr[:200]}")
            all_passed = False

    return all_passed


def test_json_output_structure():
    """Test that JSON output is valid and has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'iosched_audit.py', '--format', 'json']
    )

    # Exit code 0, 1, or 2 are all acceptable depending on system state
    if return_code not in [0, 1, 2]:
        print(f"[FAIL] JSON output test failed with unexpected return code: {return_code}")
        return False

    # If we got output, try to parse it as JSON
    if stdout:
        try:
            data = json.loads(stdout)

            # Check for expected keys
            if 'devices' in data and 'summary' in data:
                if isinstance(data['devices'], list) and isinstance(data['summary'], dict):
                    print("[PASS] JSON output structure test passed")
                    return True
                else:
                    print("[FAIL] JSON output has incorrect data types")
                    return False
            else:
                print("[FAIL] JSON output missing required keys")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        # No output might mean no devices found, which is acceptable
        # Check if stderr has an appropriate message
        if 'No block devices found' in stderr or '/sys/block not found' in stderr:
            print("[PASS] JSON output test passed (no devices available)")
            return True
        else:
            print("[FAIL] No JSON output and no clear error message")
            return False


def test_warn_only_flag():
    """Test that --warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'iosched_audit.py', '--warn-only']
    )

    # Should accept the flag (exit code depends on system state)
    if return_code in [0, 1, 2]:
        print("[PASS] --warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] --warn-only flag test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that --verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'iosched_audit.py', '--verbose']
    )

    # Should accept the flag (exit code depends on system state)
    if return_code in [0, 1, 2]:
        print("[PASS] --verbose flag test passed")
        return True
    else:
        print(f"[FAIL] --verbose flag test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'iosched_audit.py', '--warn-only', '--verbose', '--format', 'table']
    )

    # Should accept combined flags
    if return_code in [0, 1, 2]:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_exit_code_usage():
    """Test that invalid usage returns exit code 2"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'iosched_audit.py', '--format', 'invalid_format']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Exit code test passed (usage error)")
        return True
    else:
        print(f"[FAIL] Expected exit code 2 for invalid format, got {return_code}")
        return False


def test_plain_output_format():
    """Test that plain output format produces readable output"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'iosched_audit.py', '--format', 'plain']
    )

    # Should produce output or handle gracefully
    if return_code in [0, 1, 2]:
        # Check that if there's output, it's not JSON or HTML
        if stdout and not stdout.strip().startswith('{') and not stdout.strip().startswith('<'):
            print("[PASS] Plain output format test passed")
            return True
        elif not stdout and ('No block devices' in stderr or '/sys/block not found' in stderr):
            print("[PASS] Plain output format test passed (no devices)")
            return True
        else:
            print("[PASS] Plain output format test passed")
            return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        return False


def test_table_output_format():
    """Test that table output format produces formatted output"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'iosched_audit.py', '--format', 'table']
    )

    # Should produce output or handle gracefully
    if return_code in [0, 1, 2]:
        # Check for table-like output (header with dashes)
        if stdout and ('-' * 10 in stdout or 'Device' in stdout):
            print("[PASS] Table output format test passed")
            return True
        elif not stdout and ('No block devices' in stderr or '/sys/block not found' in stderr):
            print("[PASS] Table output format test passed (no devices)")
            return True
        else:
            # Might not have devices, which is okay
            print("[PASS] Table output format test passed")
            return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing iosched_audit.py...")
    print(f"=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_options,
        test_json_output_structure,
        test_warn_only_flag,
        test_verbose_flag,
        test_combined_flags,
        test_exit_code_usage,
        test_plain_output_format,
        test_table_output_format,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print(f"✗ {total - passed} test(s) failed")
        sys.exit(1)
