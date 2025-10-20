#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for system_inventory.py functionality.
Tests argument parsing and output format handling.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(cmd_args,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command([sys.executable, 'system_inventory.py', '--help'])

    if return_code == 0 and 'hardware inventory' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_plain_format():
    """Test plain text output format"""
    return_code, stdout, stderr = run_command([sys.executable, 'system_inventory.py', '--format', 'plain'])

    if return_code == 0 and 'SYSTEM INVENTORY' in stdout:
        print("[PASS] Plain format test passed")
        return True
    else:
        print("[FAIL] Plain format test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_json_format():
    """Test JSON output format"""
    return_code, stdout, stderr = run_command([sys.executable, 'system_inventory.py', '--format', 'json'])

    if return_code == 0:
        try:
            data = json.loads(stdout)
            # Check for expected keys
            if 'timestamp' in data and 'system' in data and 'cpu' in data:
                print("[PASS] JSON format test passed")
                return True
            else:
                print("[FAIL] JSON format test failed - missing expected keys")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON format test failed - invalid JSON output")
            return False
    else:
        print("[FAIL] JSON format test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([sys.executable, 'system_inventory.py', '--format', 'invalid'])

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        return False


def test_include_pci_option():
    """Test that the include-pci option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'system_inventory.py', '--include-pci'])

    # Should not fail at argument parsing level
    if return_code == 0:
        print("[PASS] Include-PCI option test passed")
        return True
    else:
        print("[FAIL] Include-PCI option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_output_file_option():
    """Test that the output file option is recognized"""
    import tempfile
    import os

    # Create a temporary file
    fd, temp_path = tempfile.mkstemp(suffix='.txt')
    os.close(fd)

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'system_inventory.py',
            '-o', temp_path
        ])

        if return_code == 0 and os.path.exists(temp_path):
            # Check if file has content
            with open(temp_path, 'r') as f:
                content = f.read()
                if len(content) > 0:
                    print("[PASS] Output file option test passed")
                    return True
                else:
                    print("[FAIL] Output file option test failed - empty file")
                    return False
        else:
            print("[FAIL] Output file option test failed with return code: " + str(return_code))
            print("stderr: " + stderr)
            return False
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_json_structure():
    """Test that JSON output has the expected structure"""
    return_code, stdout, stderr = run_command([sys.executable, 'system_inventory.py', '--format', 'json'])

    if return_code == 0:
        try:
            data = json.loads(stdout)

            # Check for required top-level keys
            required_keys = ['timestamp', 'system', 'cpu', 'memory', 'disks', 'network', 'hardware']
            missing_keys = [key for key in required_keys if key not in data]

            if not missing_keys:
                print("[PASS] JSON structure test passed")
                return True
            else:
                print("[FAIL] JSON structure test failed - missing keys: " + str(missing_keys))
                return False
        except json.JSONDecodeError as e:
            print("[FAIL] JSON structure test failed - invalid JSON: " + str(e))
            return False
    else:
        print("[FAIL] JSON structure test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'system_inventory.py',
        '--format', 'json',
        '--include-pci'
    ])

    if return_code == 0:
        try:
            data = json.loads(stdout)
            if 'pci_devices' in data:
                print("[PASS] Combined options test passed")
                return True
            else:
                print("[FAIL] Combined options test failed - PCI devices not included")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Combined options test failed - invalid JSON")
            return False
    else:
        print("[FAIL] Combined options test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


if __name__ == "__main__":
    print("Testing system_inventory.py...")

    tests = [
        test_help_message,
        test_plain_format,
        test_json_format,
        test_invalid_format,
        test_include_pci_option,
        test_output_file_option,
        test_json_structure,
        test_combined_options
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\nTest Results: " + str(passed) + "/" + str(total) + " tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
