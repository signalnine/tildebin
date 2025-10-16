#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for ec2_manage.py functionality.
Since the script relies on AWS credentials and API calls, this test will focus on:
1. Argument parsing
2. Error handling
3. Credential handling
"""

import subprocess
import sys
import os


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
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', '--help'])
    
    if return_code == 0:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_argument_parsing():
    """Test that arguments are parsed correctly"""
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', 'start', 'i-1234567890'])
    
    # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
    if return_code == 1:  # Expected - missing credentials
        print("[PASS] Argument parsing test passed (detected missing credentials correctly)")
        return True
    else:
        print("[FAIL] Argument parsing test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_invalid_action():
    """Test that invalid action option is rejected"""
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', 'invalid', 'i-1234567890'])
    
    # Should fail with argument error
    if return_code != 0:
        print("[PASS] Invalid action test passed (rejected invalid action)")
        return True
    else:
        print("[FAIL] Invalid action test failed - should have failed with invalid choice")
        return False


def test_start_action():
    """Test that the start action option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', 'start', 'i-1234567890'])
    
    # Should not fail at argument parsing level, but due to missing credentials
    if return_code == 1:  # Missing credentials error
        print("[PASS] Start action test passed")
        return True
    else:
        print("[FAIL] Start action test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_stop_action():
    """Test that the stop action option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', 'stop', 'i-1234567890'])
    
    # Should not fail at argument parsing level, but due to missing credentials
    if return_code == 1:  # Missing credentials error
        print("[PASS] Stop action test passed")
        return True
    else:
        print("[FAIL] Stop action test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_restart_action():
    """Test that the restart action option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', 'restart', 'i-1234567890'])
    
    # Should not fail at argument parsing level, but due to missing credentials
    if return_code == 1:  # Missing credentials error
        print("[PASS] Restart action test passed")
        return True
    else:
        print("[FAIL] Restart action test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_region_option():
    """Test that the region option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', 'start', 'i-1234567890', '--region', 'eu-west-1'])
    
    # Should not fail at argument parsing level, but due to missing credentials
    if return_code == 1:  # Missing credentials error
        print("[PASS] Region option test passed")
        return True
    else:
        print("[FAIL] Region option test failed with return code: " + str(return_code))
        print("stderr: " + stderr)
        return False


def test_environment_variable_handling():
    """Test that the script handles environment variables correctly"""
    # Temporarily set environment variables to test
    old_aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    old_aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    
    # Temporarily clear them
    if 'AWS_ACCESS_KEY_ID' in os.environ:
        del os.environ['AWS_ACCESS_KEY_ID']
    if 'AWS_SECRET_ACCESS_KEY' in os.environ:
        del os.environ['AWS_SECRET_ACCESS_KEY']
    
    # Test without credentials
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_manage.py', 'start', 'i-1234567890'])
    
    # Should fail due to missing credentials
    if return_code == 1:
        print("[PASS] Environment variable handling test passed (detected missing credentials)")
        success = True
    else:
        print("[FAIL] Environment variable handling test failed with return code: " + str(return_code))
        print("stdout: " + stdout)
        print("stderr: " + stderr)
        success = False
    
    # Restore original environment variables
    if old_aws_access_key:
        os.environ['AWS_ACCESS_KEY_ID'] = old_aws_access_key
    if old_aws_secret_key:
        os.environ['AWS_SECRET_ACCESS_KEY'] = old_aws_secret_key
    
    return success


if __name__ == "__main__":
    print("Testing ec2_manage.py...")
    
    tests = [
        test_help_message,
        test_argument_parsing,
        test_invalid_action,
        test_start_action,
        test_stop_action,
        test_restart_action,
        test_region_option,
        test_environment_variable_handling
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
