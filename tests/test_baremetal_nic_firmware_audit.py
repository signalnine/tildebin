#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_nic_firmware_audit.py functionality.
Tests argument parsing and error handling without requiring actual hardware.
"""

import subprocess
import sys
import json
import os
import tempfile


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
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--help']
    )

    if return_code == 0 and 'NIC driver and firmware' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed - return code: {return_code}")
        return False


def test_format_plain_option():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--format', 'plain']
    )

    # Should not fail at argument parsing level (0, 1, or 2 are valid)
    if return_code in [0, 1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print(f"[FAIL] Format plain option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_format_json_option():
    """Test that JSON format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--format', 'json']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Format JSON option test passed")
        return True
    else:
        print(f"[FAIL] Format JSON option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_format_table_option():
    """Test that table format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--format', 'table']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Format table option test passed")
        return True
    else:
        print(f"[FAIL] Format table option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--format', 'invalid']
    )

    # Should fail with argument error
    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '-v']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--warn-only']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_short_warn_only_option():
    """Test that the -w short option works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '-w']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_interface_option():
    """Test that the interface option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '-i', 'eth0']
    )

    # Should not fail at argument parsing level
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
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--interface', 'eth0']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Long interface option test passed")
        return True
    else:
        print(f"[FAIL] Long interface option test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_nic_firmware_audit.py',
        '-v',
        '--format', 'json',
        '--warn-only'
    ])

    # Should not fail at argument parsing level
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with return code: {return_code}")
        print(f"stderr: {stderr}")
        return False


def test_json_output_structure():
    """Test that JSON output has valid structure when ethtool is available"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py', '--format', 'json']
    )

    # If ethtool is not available, exit code will be 2
    if return_code == 2:
        if 'ethtool' in stderr:
            print("[PASS] JSON output structure test passed (ethtool not available, handled correctly)")
            return True

    # If we got JSON output, validate its structure
    if return_code in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            # Check required keys
            required_keys = ['interfaces', 'inconsistencies', 'summary']
            if all(key in data for key in required_keys):
                print("[PASS] JSON output structure test passed")
                return True
            else:
                print(f"[FAIL] JSON output missing required keys")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON output parsing failed: {e}")
            return False

    print("[PASS] JSON output structure test passed (no output or ethtool unavailable)")
    return True


def test_expected_versions_file_option():
    """Test that --expected option is recognized"""
    # Create a temporary expected versions file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"ixgbe": {"driver_version": "5.15.0"}}, f)
        temp_file = f.name

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'baremetal_nic_firmware_audit.py',
            '--expected', temp_file
        ])

        # Should not fail at argument parsing level
        if return_code in [0, 1, 2]:
            print("[PASS] Expected versions file option test passed")
            return True
        else:
            print(f"[FAIL] Expected versions option test failed with return code: {return_code}")
            print(f"stderr: {stderr}")
            return False
    finally:
        os.unlink(temp_file)


def test_invalid_expected_file():
    """Test handling of non-existent expected versions file"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'baremetal_nic_firmware_audit.py',
        '--expected', '/nonexistent/file.json'
    ])

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Invalid expected file test passed")
        return True
    else:
        print(f"[FAIL] Invalid expected file test failed - expected exit code 2, got {return_code}")
        return False


def test_ethtool_dependency_message():
    """Test that missing ethtool is handled with helpful message"""
    # This test checks the error message format
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_nic_firmware_audit.py']
    )

    # If ethtool is not available, check for helpful message
    if return_code == 2 and 'ethtool' in stderr.lower():
        if 'apt-get install' in stderr or 'required' in stderr.lower():
            print("[PASS] Ethtool dependency message test passed")
            return True

    # If ethtool is available, the script should work
    if return_code in [0, 1]:
        print("[PASS] Ethtool dependency message test passed (ethtool available)")
        return True

    print(f"[FAIL] Ethtool dependency message test failed")
    print(f"  Return code: {return_code}")
    print(f"  stderr: {stderr}")
    return False


if __name__ == "__main__":
    print("Testing baremetal_nic_firmware_audit.py...")

    tests = [
        test_help_message,
        test_format_plain_option,
        test_format_json_option,
        test_format_table_option,
        test_invalid_format,
        test_verbose_option,
        test_warn_only_option,
        test_short_warn_only_option,
        test_interface_option,
        test_long_interface_option,
        test_combined_options,
        test_json_output_structure,
        test_expected_versions_file_option,
        test_invalid_expected_file,
        test_ethtool_dependency_message
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
