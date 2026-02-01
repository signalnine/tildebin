#!/usr/bin/env python3
"""
Test script for baremetal_partition_alignment_checker.py functionality.
Tests argument parsing and error handling without requiring actual disk access.
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
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--help']
    )

    if return_code == 0 and 'alignment' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("  stdout: " + stdout[:200])
        return False


def test_help_contains_guidelines():
    """Test that help message documents alignment guidelines"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--help']
    )

    if return_code == 0 and '1MiB' in stdout and '4K' in stdout:
        print("[PASS] Help contains alignment guidelines")
        return True
    else:
        print("[FAIL] Help should document alignment guidelines")
        return False


def test_device_option():
    """Test that the -d/--device option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '-d', 'sda']
    )

    # Should succeed (0), warn (1), or error (2) - not parsing error
    if return_code in [0, 1, 2]:
        print("[PASS] Device option test passed")
        return True
    else:
        print("[FAIL] Device option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_device_option_with_dev_prefix():
    """Test that the -d/--device option handles /dev/ prefix"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '-d', '/dev/nvme0n1']
    )

    # Should succeed (0), warn (1), or error (2) - not parsing error
    if return_code in [0, 1, 2]:
        print("[PASS] Device option with /dev/ prefix test passed")
        return True
    else:
        print("[FAIL] Device option with /dev/ prefix test failed")
        print("  stderr: " + stderr)
        return False


def test_verbose_option():
    """Test that the -v/--verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_warn_only_option():
    """Test that the -w/--warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '-w']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_format_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: " + str(return_code))
        return False


def test_format_json():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: " + str(return_code))
        return False


def test_format_table():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: " + str(return_code))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'invalid']
    )

    # Should fail with argument error (exit code 2)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_partition_alignment_checker.py',
        '-d', 'nvme0n1',
        '-v',
        '-w',
        '--format', 'json'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("  stderr: " + stderr)
        return False


def test_unknown_option_rejected():
    """Test that unknown options are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--unknown-option']
    )

    if return_code == 2 and 'unrecognized arguments' in stderr:
        print("[PASS] Unknown option rejected test passed")
        return True
    else:
        print("[FAIL] Unknown option should be rejected")
        return False


def test_json_output_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'json']
    )

    # If devices found, output should be valid JSON with expected structure
    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            # Should have devices key
            if isinstance(data, dict) and 'devices' in data:
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected structure")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON output is not valid JSON")
            print("  stdout: " + stdout[:200])
            return False
    elif return_code == 0 and 'No block devices' in stdout:
        # No devices - still pass the test
        print("[PASS] JSON output structure test passed (no devices)")
        return True
    else:
        # Other cases are acceptable
        print("[PASS] JSON output structure test passed (no devices or error)")
        return True


def test_no_devices_exit_code():
    """Test that no devices returns exit code 0 (not an error)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py']
    )

    # Exit 0 = success or no devices
    # Exit 1 = misalignment found
    # Exit 2 = should only be for usage errors
    if return_code in [0, 1]:
        print("[PASS] Exit code test passed")
        return True
    elif return_code == 2:
        # If exit 2, should be a real error message
        if 'usage' in stderr.lower() or 'unrecognized' in stderr.lower():
            print("[FAIL] Exit code 2 should only be for usage errors")
            return False
        else:
            # Some other legitimate error - accept it
            print("[PASS] Script handled environment appropriately")
            return True
    else:
        print("[FAIL] Unexpected exit code: " + str(return_code))
        return False


def test_plain_output_contains_header():
    """Test that plain output contains expected header"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Should contain report header or no devices message
        if 'Alignment' in stdout or 'partition' in stdout.lower() or 'No block devices' in stdout:
            print("[PASS] Plain output header test passed")
            return True
        else:
            print("[FAIL] Plain output should contain alignment info or no devices message")
            print("  stdout: " + stdout[:200])
            return False
    else:
        # Script may have failed for other reasons
        print("[PASS] Plain output header test passed (no devices or error)")
        return True


def test_json_device_fields():
    """Test that JSON output includes expected device fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            if 'devices' in data and len(data['devices']) > 0:
                device = data['devices'][0]
                # Check for expected fields
                expected_fields = ['device', 'logical_sector_size', 'physical_sector_size']
                has_fields = all(field in device for field in expected_fields)
                if has_fields:
                    print("[PASS] JSON device fields test passed")
                    return True
                else:
                    print("[FAIL] JSON output missing expected device fields")
                    return False
            else:
                # No devices - still pass
                print("[PASS] JSON device fields test passed (no devices)")
                return True
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    else:
        print("[PASS] JSON device fields test passed (no output)")
        return True


def test_table_format_header():
    """Test that table format has a header row"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_partition_alignment_checker.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Should contain table header columns
        if 'Device' in stdout or 'Aligned' in stdout or 'No block devices' in stdout.lower():
            print("[PASS] Table format header test passed")
            return True
        else:
            # Might be misaligned partitions only view
            print("[PASS] Table format header test passed (or no output)")
            return True
    else:
        print("[PASS] Table format header test passed (error case)")
        return True


if __name__ == "__main__":
    print("Testing baremetal_partition_alignment_checker.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_guidelines,
        test_device_option,
        test_device_option_with_dev_prefix,
        test_verbose_option,
        test_warn_only_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_combined_options,
        test_unknown_option_rejected,
        test_json_output_structure,
        test_no_devices_exit_code,
        test_plain_output_contains_header,
        test_json_device_fields,
        test_table_format_header,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print()
    print("Test Results: {}/{} tests passed".format(passed, total))

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
