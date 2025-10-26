#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for sysctl_audit.py functionality.
Tests argument parsing and error handling without requiring actual sysctl changes.
"""

import subprocess
import sys
import os
import tempfile


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
    return_code, stdout, stderr = run_command([sys.executable, 'sysctl_audit.py', '--help'])

    if return_code == 0 and 'Audit kernel parameters' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_no_arguments():
    """Test that running without arguments shows an error"""
    return_code, stdout, stderr = run_command([sys.executable, 'sysctl_audit.py'])

    # Should fail because no baseline or save specified, or sysctl not found
    if return_code != 0 and ('baseline' in stderr.lower() or 'baseline' in stdout.lower() or 'sysctl' in stderr.lower()):
        print("[PASS] No arguments test passed")
        return True
    else:
        print("[FAIL] No arguments test failed - should require baseline or save")
        return False


def test_save_baseline():
    """Test that --save creates a baseline file"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.baseline') as f:
        baseline_file = f.name

    try:
        return_code, stdout, stderr = run_command([sys.executable, 'sysctl_audit.py', '--save', baseline_file])

        # Should succeed and create file, or fail if sysctl not available
        if return_code == 0:
            if os.path.exists(baseline_file):
                with open(baseline_file, 'r') as f:
                    content = f.read()
                    if len(content) > 0 and '=' in content:
                        print("[PASS] Save baseline test passed")
                        return True
        elif 'sysctl' in stderr.lower():
            # sysctl not available in this environment
            print("[PASS] Save baseline test passed (sysctl not available)")
            return True

        print("[FAIL] Save baseline test failed - file not created or empty")
        return False
    finally:
        if os.path.exists(baseline_file):
            os.unlink(baseline_file)


def test_baseline_format():
    """Test that saved baseline has correct format"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.baseline') as f:
        baseline_file = f.name

    try:
        # Create a baseline
        return_code, stdout, stderr = run_command([sys.executable, 'sysctl_audit.py', '--save', baseline_file])

        if return_code == 0 and os.path.exists(baseline_file):
            with open(baseline_file, 'r') as f:
                lines = f.readlines()

                # Should have header comments and parameters
                has_comment = any(line.startswith('#') for line in lines)
                has_parameters = any('=' in line and not line.startswith('#') for line in lines)

                if has_comment and has_parameters:
                    print("[PASS] Baseline format test passed")
                    return True
        elif 'sysctl' in stderr.lower():
            # sysctl not available in this environment
            print("[PASS] Baseline format test passed (sysctl not available)")
            return True

        print("[FAIL] Baseline format test failed")
        return False
    finally:
        if os.path.exists(baseline_file):
            os.unlink(baseline_file)


def test_baseline_comparison():
    """Test comparing against a baseline"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.baseline') as f:
        baseline_file = f.name
        # Write a simple baseline with a common parameter
        f.write("# Test baseline\n")
        f.write("net.ipv4.ip_forward=0\n")

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'sysctl_audit.py',
            '--baseline', baseline_file
        ])

        # Should complete (may show mismatches) or fail if sysctl not available
        if return_code in [0, 1]:
            print("[PASS] Baseline comparison test passed")
            return True
        elif return_code == 2 and 'sysctl' in stderr.lower():
            # sysctl not available in this environment
            print("[PASS] Baseline comparison test passed (sysctl not available)")
            return True
        else:
            print("[FAIL] Baseline comparison test failed - return code: " + str(return_code))
            return False
    finally:
        if os.path.exists(baseline_file):
            os.unlink(baseline_file)


def test_parameter_lookup():
    """Test looking up a specific parameter"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'sysctl_audit.py',
        '--parameter', 'net.ipv4.ip_forward'
    ])

    # Should succeed or fail gracefully, or fail if sysctl not available
    if return_code in [0, 1]:
        print("[PASS] Parameter lookup test passed")
        return True
    elif return_code == 2 and 'sysctl' in stderr.lower():
        # sysctl not available in this environment
        print("[PASS] Parameter lookup test passed (sysctl not available)")
        return True
    else:
        print("[FAIL] Parameter lookup test failed - return code: " + str(return_code))
        return False


def test_parameter_format_json():
    """Test JSON output format for parameter lookup"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'sysctl_audit.py',
        '--parameter', 'net.ipv4.ip_forward',
        '--format', 'json'
    ])

    # Should succeed and output valid JSON or fail with code 1
    if return_code == 0 and '{' in stdout:
        print("[PASS] Parameter format JSON test passed")
        return True
    elif return_code == 1:
        # Parameter may not exist
        print("[PASS] Parameter format JSON test passed (parameter not found)")
        return True
    elif return_code == 2 and 'sysctl' in stderr.lower():
        # sysctl not available in this environment
        print("[PASS] Parameter format JSON test passed (sysctl not available)")
        return True
    else:
        print("[FAIL] Parameter format JSON test failed")
        return False


def test_verbose_option():
    """Test that verbose option is recognized"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.baseline') as f:
        baseline_file = f.name
        f.write("# Test baseline\n")
        f.write("net.ipv4.ip_forward=0\n")

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'sysctl_audit.py',
            '--baseline', baseline_file,
            '--verbose'
        ])

        if return_code in [0, 1]:
            print("[PASS] Verbose option test passed")
            return True
        elif return_code == 2 and 'sysctl' in stderr.lower():
            # sysctl not available in this environment
            print("[PASS] Verbose option test passed (sysctl not available)")
            return True
        else:
            print("[FAIL] Verbose option test failed")
            return False
    finally:
        if os.path.exists(baseline_file):
            os.unlink(baseline_file)


def test_warn_only_option():
    """Test that warn-only option is recognized"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.baseline') as f:
        baseline_file = f.name
        f.write("# Test baseline\n")
        f.write("net.ipv4.ip_forward=0\n")

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'sysctl_audit.py',
            '--baseline', baseline_file,
            '--warn-only'
        ])

        if return_code in [0, 1]:
            print("[PASS] Warn-only option test passed")
            return True
        elif return_code == 2 and 'sysctl' in stderr.lower():
            # sysctl not available in this environment
            print("[PASS] Warn-only option test passed (sysctl not available)")
            return True
        else:
            print("[FAIL] Warn-only option test failed")
            return False
    finally:
        if os.path.exists(baseline_file):
            os.unlink(baseline_file)


def test_format_json_option():
    """Test JSON output format"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.baseline') as f:
        baseline_file = f.name
        f.write("# Test baseline\n")
        f.write("net.ipv4.ip_forward=0\n")

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'sysctl_audit.py',
            '--baseline', baseline_file,
            '--format', 'json'
        ])

        if return_code in [0, 1] and ('[' in stdout or '{' in stdout):
            print("[PASS] Format JSON option test passed")
            return True
        elif return_code == 2 and 'sysctl' in stderr.lower():
            # sysctl not available in this environment
            print("[PASS] Format JSON option test passed (sysctl not available)")
            return True
        else:
            print("[FAIL] Format JSON option test failed")
            return False
    finally:
        if os.path.exists(baseline_file):
            os.unlink(baseline_file)


def test_combined_options():
    """Test combining multiple options"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.baseline') as f:
        baseline_file = f.name
        f.write("# Test baseline\n")
        f.write("net.ipv4.ip_forward=0\n")

    try:
        return_code, stdout, stderr = run_command([
            sys.executable, 'sysctl_audit.py',
            '--baseline', baseline_file,
            '--verbose',
            '--format', 'json',
            '--warn-only'
        ])

        if return_code in [0, 1]:
            print("[PASS] Combined options test passed")
            return True
        elif return_code == 2 and 'sysctl' in stderr.lower():
            # sysctl not available in this environment
            print("[PASS] Combined options test passed (sysctl not available)")
            return True
        else:
            print("[FAIL] Combined options test failed")
            return False
    finally:
        if os.path.exists(baseline_file):
            os.unlink(baseline_file)


def test_invalid_baseline_file():
    """Test that invalid baseline file is handled"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'sysctl_audit.py',
        '--baseline', '/nonexistent/path/to/baseline'
    ])

    # Should fail with error code 2
    if return_code == 2 and ('not found' in stderr.lower() or 'not found' in stdout.lower()):
        print("[PASS] Invalid baseline file test passed")
        return True
    else:
        print("[FAIL] Invalid baseline file test failed - should return error code 2")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'sysctl_audit.py',
        '--format', 'invalid'
    ])

    # Should fail with argument error
    if return_code != 0 and ('invalid choice' in stderr or 'invalid choice' in stdout):
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed")
        return False


if __name__ == "__main__":
    print("Testing sysctl_audit.py...")

    tests = [
        test_help_message,
        test_no_arguments,
        test_save_baseline,
        test_baseline_format,
        test_baseline_comparison,
        test_parameter_lookup,
        test_parameter_format_json,
        test_verbose_option,
        test_warn_only_option,
        test_format_json_option,
        test_combined_options,
        test_invalid_baseline_file,
        test_invalid_format
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
