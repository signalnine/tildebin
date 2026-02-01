#!/usr/bin/env python3
"""
Test script for baremetal_scsi_error_monitor.py functionality.
Tests argument parsing and output formats without requiring actual SCSI devices.
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
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--help']
    )

    if return_code == 0 and 'scsi' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--help']
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
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print("[FAIL] Help exit codes test failed")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--format', 'xml']
    )

    # Should fail with exit code 2 (usage error)
    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_format_options():
    """Test that format options are recognized"""
    formats = ['plain', 'json', 'table']
    results = []

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_scsi_error_monitor.py', '--format', fmt]
        )

        # Return code should be 0 (success), 1 (warnings), or 2 (missing scsi_device)
        # but not negative (crash)
        if return_code in (0, 1, 2):
            results.append(True)
        else:
            print(f"[FAIL] Format {fmt} crashed with code {return_code}")
            results.append(False)

    if all(results):
        print("[PASS] Format options test passed")
        return True
    else:
        print(f"[FAIL] Format options test failed: {sum(results)}/{len(results)} passed")
        return False


def test_verbose_flag():
    """Test that verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '-v']
    )

    # Should parse successfully (exit 0, 1, or 2)
    if return_code in (0, 1, 2):
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed with code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '-w']
    )

    # Should parse successfully (exit 0, 1, or 2)
    if return_code in (0, 1, 2):
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_disks_only_flag():
    """Test that --disks-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--disks-only']
    )

    # Should parse successfully (exit 0, 1, or 2)
    if return_code in (0, 1, 2):
        print("[PASS] Disks-only flag test passed")
        return True
    else:
        print(f"[FAIL] Disks-only flag test failed with code {return_code}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--format', 'json']
    )

    # If successful (exit 0 or 1), try to parse JSON
    if return_code in (0, 1):
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                print("[PASS] JSON output format test passed")
                return True
            else:
                print(f"[FAIL] JSON output is not a list: {type(data)}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Missing /sys/class/scsi_device is acceptable in test environment
        print("[PASS] JSON output format test passed (no SCSI devices available)")
        return True
    else:
        print(f"[FAIL] JSON output format test failed with code {return_code}")
        return False


def test_json_output_structure():
    """Test that JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--format', 'json']
    )

    if return_code in (0, 1):
        try:
            data = json.loads(stdout)
            if isinstance(data, list) and len(data) > 0:
                # Check first item has expected fields
                item = data[0]
                expected_fields = ['scsi_id', 'vendor', 'model', 'status', 'counters']
                missing = [f for f in expected_fields if f not in item]
                if not missing:
                    print("[PASS] JSON output structure test passed")
                    return True
                else:
                    print(f"[FAIL] JSON missing fields: {missing}")
                    return False
            elif isinstance(data, list) and len(data) == 0:
                # Empty list is valid if no devices have warnings
                print("[PASS] JSON output structure test passed (empty list)")
                return True
            else:
                print(f"[FAIL] Unexpected JSON format")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] JSON output structure test passed (no SCSI devices)")
        return True
    else:
        print(f"[FAIL] JSON output structure test failed with code {return_code}")
        return False


def test_combined_flags():
    """Test combination of multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py',
         '--format', 'json', '-v', '-w']
    )

    # Should parse successfully
    if return_code in (0, 1, 2):
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed with code {return_code}")
        return False


def test_combined_flags_with_disks_only():
    """Test combination of flags including --disks-only"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py',
         '--format', 'table', '--disks-only', '-w']
    )

    # Should parse successfully
    if return_code in (0, 1, 2):
        print("[PASS] Combined flags with disks-only test passed")
        return True
    else:
        print(f"[FAIL] Combined flags with disks-only test failed with code {return_code}")
        return False


def test_exit_code_convention():
    """Test that exit codes follow convention (0=success, 1=issues, 2=error)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py']
    )

    if return_code in (0, 1, 2):
        print("[PASS] Exit code convention test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_missing_sysfs_handled():
    """Test that missing /sys/class/scsi_device is handled gracefully"""
    # This test verifies error handling - the script should exit 2 if
    # no SCSI devices are available, not crash
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py']
    )

    # Should not crash (return code should be 0, 1, or 2)
    if return_code in (0, 1, 2):
        print("[PASS] Missing sysfs handling test passed")
        return True
    else:
        print(f"[FAIL] Script crashed with code {return_code}")
        return False


def test_error_counter_documentation():
    """Test that help documents what error counters mean"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scsi_error_monitor.py', '--help']
    )

    if return_code == 0:
        # Check for documentation of key counters
        has_ioerr = 'ioerr_cnt' in stdout
        has_iotmo = 'iotmo_cnt' in stdout
        if has_ioerr and has_iotmo:
            print("[PASS] Error counter documentation test passed")
            return True
        else:
            print("[FAIL] Missing error counter documentation")
            return False
    else:
        print(f"[FAIL] Help failed with code {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_scsi_error_monitor.py...\n")

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_invalid_format_option,
        test_format_options,
        test_verbose_flag,
        test_warn_only_flag,
        test_disks_only_flag,
        test_json_output_format,
        test_json_output_structure,
        test_combined_flags,
        test_combined_flags_with_disks_only,
        test_exit_code_convention,
        test_missing_sysfs_handled,
        test_error_counter_documentation,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
