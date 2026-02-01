#!/usr/bin/env python3
"""
Test script for baremetal_efi_boot_audit.py functionality.
Tests argument parsing and error handling without requiring EFI system.
"""

import subprocess
import sys
import json
import os


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
        [sys.executable, 'baremetal_efi_boot_audit.py', '--help']
    )

    if return_code == 0 and 'efi' in stdout.lower() and 'boot' in stdout.lower():
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
        [sys.executable, 'baremetal_efi_boot_audit.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_plain():
    """Test that --format plain option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_efi_boot_audit.py', '--format', 'plain', '--help']
    )

    # Help should still work with format option
    if return_code == 0:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print(f"[FAIL] Format plain option test failed: {return_code}")
        return False


def test_format_option_json():
    """Test that --format json option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_efi_boot_audit.py', '--format', 'json', '--help']
    )

    if return_code == 0:
        print("[PASS] Format json option test passed")
        return True
    else:
        print(f"[FAIL] Format json option test failed: {return_code}")
        return False


def test_format_option_table():
    """Test that --format table option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_efi_boot_audit.py', '--format', 'table', '--help']
    )

    if return_code == 0:
        print("[PASS] Format table option test passed")
        return True
    else:
        print(f"[FAIL] Format table option test failed: {return_code}")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_efi_boot_audit.py', '--format', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_verbose_option():
    """Test that --verbose option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_efi_boot_audit.py', '--verbose', '--help']
    )

    if return_code == 0 and 'verbose' in stdout.lower():
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed: {return_code}")
        return False


def test_warn_only_option():
    """Test that --warn-only option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_efi_boot_audit.py', '--warn-only', '--help']
    )

    if return_code == 0 and 'warn' in stdout.lower():
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed: {return_code}")
        return False


def test_non_efi_system_handling():
    """Test graceful handling on non-EFI systems."""
    # If /sys/firmware/efi doesn't exist, script should exit with code 2
    if not os.path.exists('/sys/firmware/efi'):
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_efi_boot_audit.py']
        )

        if return_code == 2 and ('efi' in stderr.lower() or 'uefi' in stderr.lower()):
            print("[PASS] Non-EFI system handling test passed")
            return True
        else:
            print(f"[FAIL] Non-EFI system should exit with code 2")
            print(f"  Return code: {return_code}")
            print(f"  Stderr: {stderr[:200]}")
            return False
    else:
        # System is EFI, skip this test
        print("[SKIP] System is EFI, skipping non-EFI test")
        return True


def test_efi_system_execution():
    """Test execution on EFI systems (if applicable)."""
    if os.path.exists('/sys/firmware/efi'):
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_efi_boot_audit.py']
        )

        # Should return 0, 1, or 2 (if efibootmgr not installed)
        if return_code in [0, 1, 2]:
            # If exit code is 2, check it's due to missing efibootmgr
            if return_code == 2:
                if 'efibootmgr' in stderr.lower():
                    print("[PASS] EFI system test passed (efibootmgr not installed)")
                    return True
                else:
                    print(f"[FAIL] Unexpected error: {stderr[:200]}")
                    return False
            else:
                # Check for expected output
                if 'Boot' in stdout or 'Secure Boot' in stdout or stdout == '':
                    print("[PASS] EFI system execution test passed")
                    return True
                else:
                    print(f"[FAIL] Unexpected output: {stdout[:200]}")
                    return False
        else:
            print(f"[FAIL] Unexpected return code: {return_code}")
            return False
    else:
        print("[SKIP] System is not EFI, skipping EFI execution test")
        return True


def test_json_output_structure():
    """Test JSON output structure on EFI systems."""
    if os.path.exists('/sys/firmware/efi'):
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_efi_boot_audit.py', '--format', 'json']
        )

        if return_code == 2:
            # efibootmgr not installed, skip
            print("[SKIP] efibootmgr not installed, skipping JSON structure test")
            return True

        try:
            data = json.loads(stdout)

            # Check for expected keys
            if 'boot_config' not in data or 'issues' not in data:
                print("[FAIL] JSON output missing expected keys")
                print(f"  Keys: {list(data.keys())}")
                return False

            boot_config = data['boot_config']
            expected_keys = ['boot_current', 'boot_order', 'secure_boot', 'entries']
            if not all(key in boot_config for key in expected_keys):
                print("[FAIL] JSON boot_config missing expected keys")
                print(f"  Keys: {list(boot_config.keys())}")
                return False

            print("[PASS] JSON output structure test passed")
            return True

        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print("[SKIP] System is not EFI, skipping JSON structure test")
        return True


def test_short_options():
    """Test short option forms."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_efi_boot_audit.py', '-v', '-w', '--help']
    )

    if return_code == 0:
        print("[PASS] Short options test passed")
        return True
    else:
        print(f"[FAIL] Short options test failed: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_efi_boot_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format_option,
        test_verbose_option,
        test_warn_only_option,
        test_short_options,
        test_non_efi_system_handling,
        test_efi_system_execution,
        test_json_output_structure,
    ]

    passed = 0
    skipped = 0
    failed = 0

    for test in tests:
        result = test()
        if result is True:
            passed += 1
        elif result is None:
            skipped += 1
        else:
            failed += 1

    total = len(tests)
    print()
    print(f"Test Results: {passed} passed, {failed} failed, {skipped} skipped out of {total}")

    if failed == 0:
        print("All applicable tests passed!")
        sys.exit(0)
    else:
        print(f"{failed} test(s) failed")
        sys.exit(1)
