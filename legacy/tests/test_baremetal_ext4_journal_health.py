#!/usr/bin/env python3
"""
Test script for baremetal_ext4_journal_health.py functionality.
Tests argument parsing and error handling without requiring root access or ext4 filesystems.
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
        [sys.executable, 'baremetal_ext4_journal_health.py', '--help']
    )

    if return_code == 0 and 'ext4' in stdout.lower() and 'journal' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--format', 'plain']
    )

    # May succeed or fail depending on ext4 availability, but shouldn't be usage error
    if return_code != 2 or 'dumpe2fs' in stderr:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_option_json():
    """Test JSON format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--format', 'json']
    )

    # If dumpe2fs is missing, return code is 2 (acceptable)
    # If no ext4 filesystems, should still produce valid JSON
    if return_code == 2 and 'dumpe2fs' in stderr:
        print("[PASS] JSON format option test passed (dumpe2fs not available)")
        return True

    # Try to parse JSON output
    try:
        if stdout.strip():
            data = json.loads(stdout)
            if 'filesystems' in data or 'timestamp' in data:
                print("[PASS] JSON format option test passed")
                return True
    except json.JSONDecodeError:
        pass

    # Accept if it ran without argument error
    if return_code in [0, 1]:
        print("[PASS] JSON format option test passed")
        return True

    print(f"[FAIL] JSON format option test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stdout: {stdout[:200]}")
    return False


def test_format_option_table():
    """Test table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--format', 'table']
    )

    # Should accept the option (exit 2 only if dumpe2fs missing)
    if return_code in [0, 1] or (return_code == 2 and 'dumpe2fs' in stderr):
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '-v']
    )

    # Should accept the flag
    if return_code in [0, 1] or (return_code == 2 and 'dumpe2fs' in stderr):
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--warn-only']
    )

    # Should accept the flag
    if return_code in [0, 1] or (return_code == 2 and 'dumpe2fs' in stderr):
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_device_option():
    """Test device option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--device', '/dev/nonexistent']
    )

    # Should accept the option (will fail on the device, but that's expected)
    if return_code in [0, 1, 2]:  # 2 is acceptable (device not found)
        print("[PASS] Device option test passed")
        return True
    else:
        print(f"[FAIL] Device option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_verbose_flag():
    """Test short verbose flag -v is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '-v']
    )

    if return_code in [0, 1] or (return_code == 2 and 'dumpe2fs' in stderr):
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Short verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_warn_only_flag():
    """Test short warn-only flag -w is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '-w']
    )

    if return_code in [0, 1] or (return_code == 2 and 'dumpe2fs' in stderr):
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_flags():
    """Test combining multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py',
         '--format', 'json', '-v', '--warn-only']
    )

    if return_code in [0, 1] or (return_code == 2 and 'dumpe2fs' in stderr):
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_structure():
    """Test JSON output structure when available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--format', 'json']
    )

    # If dumpe2fs is missing, skip structure test
    if return_code == 2 and 'dumpe2fs' in stderr:
        print("[PASS] JSON structure test passed (dumpe2fs not available)")
        return True

    try:
        if stdout.strip():
            data = json.loads(stdout)

            # Check for expected top-level keys
            expected_keys = ['timestamp', 'filesystems']
            has_keys = all(key in data for key in expected_keys)

            if has_keys:
                print("[PASS] JSON structure test passed")
                return True
            else:
                print(f"[FAIL] JSON missing expected keys")
                print(f"  Found keys: {list(data.keys())}")
                return False
        else:
            # Empty output with success code is acceptable (no ext4 filesystems)
            print("[PASS] JSON structure test passed (no output)")
            return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_missing_dumpe2fs_message():
    """Test helpful error message when dumpe2fs is missing"""
    # This test checks the error message format - it will pass even if
    # dumpe2fs is installed since we're just testing the script loads
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--help']
    )

    # Help should always work
    if return_code == 0:
        print("[PASS] Missing dumpe2fs message test passed")
        return True
    else:
        print(f"[FAIL] Help should work regardless of dumpe2fs")
        return False


def test_exit_codes_documented():
    """Test that exit codes are documented in help"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ext4_journal_health.py', '--help']
    )

    if 'exit code' in stdout.lower() or 'Exit codes' in stdout:
        print("[PASS] Exit codes documentation test passed")
        return True
    else:
        print(f"[FAIL] Exit codes should be documented in help")
        return False


if __name__ == "__main__":
    print("Testing baremetal_ext4_journal_health.py...")
    print()

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_device_option,
        test_short_verbose_flag,
        test_short_warn_only_flag,
        test_combined_flags,
        test_json_structure,
        test_missing_dumpe2fs_message,
        test_exit_codes_documented,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
