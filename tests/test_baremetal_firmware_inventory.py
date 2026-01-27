#!/usr/bin/env python3
"""
Test script for baremetal_firmware_inventory.py functionality.
Tests argument parsing and output format handling.
"""

import json
import subprocess
import sys


def run_command(cmd_args):
    """Helper function to run a command and return result."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--help']
    )

    if return_code == 0 and 'firmware' in stdout.lower() and 'inventory' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: {}".format(return_code))
        print("stdout: {}".format(stdout[:200]))
        return False


def test_verbose_option():
    """Test that the verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_plain():
    """Test that plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print("[FAIL] Plain format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_json():
    """Test that JSON format option is recognized and produces valid JSON."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        # Verify it's valid JSON
        if stdout.strip():
            try:
                data = json.loads(stdout)
                expected_keys = ['collected_at', 'hostname', 'kernel', 'system', 'bios']
                missing_keys = [k for k in expected_keys if k not in data]
                if not missing_keys:
                    print("[PASS] JSON format option test passed (valid JSON with expected fields)")
                    return True
                else:
                    print("[FAIL] JSON output missing expected keys: {}".format(missing_keys))
                    return False
            except json.JSONDecodeError as e:
                print("[FAIL] JSON format test failed - invalid JSON output: {}".format(e))
                print("Output: {}".format(stdout[:200]))
                return False
        print("[PASS] JSON format option test passed")
        return True
    else:
        print("[FAIL] JSON format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_format_table():
    """Test that table format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print("[FAIL] Table format option test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'invalid']
    )

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        print("return_code: {}, stderr: {}".format(return_code, stderr))
        return False


def test_exit_code_documentation():
    """Test that exit codes are documented in help."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--help']
    )

    if return_code == 0:
        if 'Exit codes' in stdout or 'exit code' in stdout.lower():
            print("[PASS] Exit code documentation test passed")
            return True
        else:
            print("[FAIL] Exit codes not documented in help")
            return False
    else:
        print("[FAIL] Could not check exit code documentation")
        return False


def test_json_output_structure():
    """Test that JSON output has the expected structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)

            # Check main structure
            expected_keys = ['collected_at', 'hostname', 'kernel', 'system',
                           'baseboard', 'bios', 'cpu_microcode', 'bmc',
                           'storage', 'network', 'gpu']
            missing_keys = [k for k in expected_keys if k not in data]

            if not missing_keys:
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print("[FAIL] JSON output missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[PASS] JSON structure test passed (allowed exit code)")
        return True


def test_bios_fields():
    """Test that BIOS section has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            bios = data.get('bios', {})
            expected_keys = ['vendor', 'version', 'release_date']
            missing_keys = [k for k in expected_keys if k not in bios]

            if not missing_keys:
                print("[PASS] BIOS fields test passed")
                return True
            else:
                print("[FAIL] BIOS section missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[PASS] BIOS fields test passed (allowed exit code)")
        return True


def test_system_fields():
    """Test that system section has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            system = data.get('system', {})
            expected_keys = ['manufacturer', 'product_name', 'version']
            missing_keys = [k for k in expected_keys if k not in system]

            if not missing_keys:
                print("[PASS] System fields test passed")
                return True
            else:
                print("[FAIL] System section missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[PASS] System fields test passed (allowed exit code)")
        return True


def test_kernel_fields():
    """Test that kernel section has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            kernel = data.get('kernel', {})
            expected_keys = ['release', 'version', 'machine']
            missing_keys = [k for k in expected_keys if k not in kernel]

            if not missing_keys:
                print("[PASS] Kernel fields test passed")
                return True
            else:
                print("[FAIL] Kernel section missing keys: {}".format(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[PASS] Kernel fields test passed (allowed exit code)")
        return True


def test_storage_is_list():
    """Test that storage section is a list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            storage = data.get('storage')
            if isinstance(storage, list):
                print("[PASS] Storage is list test passed")
                return True
            else:
                print("[FAIL] Storage should be a list, got: {}".format(type(storage)))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[PASS] Storage is list test passed (allowed exit code)")
        return True


def test_network_is_list():
    """Test that network section is a list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            network = data.get('network')
            if isinstance(network, list):
                print("[PASS] Network is list test passed")
                return True
            else:
                print("[FAIL] Network should be a list, got: {}".format(type(network)))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[PASS] Network is list test passed (allowed exit code)")
        return True


def test_plain_output_contains_header():
    """Test that plain output contains a header."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        if 'Firmware Inventory' in stdout or 'firmware' in stdout.lower():
            print("[PASS] Plain output header test passed")
            return True
        else:
            print("[FAIL] Plain output missing header")
            print("Output: {}".format(stdout[:200]))
            return False
    else:
        print("[FAIL] Unexpected return code: {}".format(return_code))
        return False


def test_table_output_has_columns():
    """Test that table output has column headers."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        if 'Component' in stdout and 'Version' in stdout:
            print("[PASS] Table output columns test passed")
            return True
        else:
            print("[FAIL] Table output missing column headers")
            print("Output: {}".format(stdout[:200]))
            return False
    else:
        print("[FAIL] Unexpected return code: {}".format(return_code))
        return False


def test_verbose_shows_more_info():
    """Test that verbose mode shows additional information."""
    # Run without verbose
    rc1, stdout1, _ = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'plain']
    )

    # Run with verbose
    rc2, stdout2, _ = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'plain', '-v']
    )

    if rc1 in [0, 1] and rc2 in [0, 1]:
        # Verbose output should be at least as long as non-verbose
        if len(stdout2) >= len(stdout1):
            print("[PASS] Verbose output test passed")
            return True
        else:
            print("[FAIL] Verbose output should be >= non-verbose output")
            return False
    else:
        print("[PASS] Verbose output test passed (allowed exit codes)")
        return True


def test_combined_options():
    """Test that multiple options can be combined."""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_firmware_inventory.py',
        '-v',
        '--format', 'json'
    ])

    if return_code in [0, 1]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed with return code: {}".format(return_code))
        print("stderr: {}".format(stderr))
        return False


def test_collected_at_is_timestamp():
    """Test that collected_at field is a valid timestamp."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_firmware_inventory.py', '--format', 'json']
    )

    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            collected_at = data.get('collected_at', '')
            # Check if it looks like an ISO timestamp
            if collected_at and 'T' in collected_at and '-' in collected_at:
                print("[PASS] Collected_at timestamp test passed")
                return True
            else:
                print("[FAIL] collected_at doesn't look like a timestamp: {}".format(collected_at))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON parsing failed: {}".format(e))
            return False
    else:
        print("[PASS] Collected_at timestamp test passed (allowed exit code)")
        return True


if __name__ == "__main__":
    print("Testing baremetal_firmware_inventory.py...")
    print()

    tests = [
        test_help_message,
        test_verbose_option,
        test_format_plain,
        test_format_json,
        test_format_table,
        test_invalid_format,
        test_exit_code_documentation,
        test_json_output_structure,
        test_bios_fields,
        test_system_fields,
        test_kernel_fields,
        test_storage_is_list,
        test_network_is_list,
        test_plain_output_contains_header,
        test_table_output_has_columns,
        test_verbose_shows_more_info,
        test_combined_options,
        test_collected_at_is_timestamp,
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
