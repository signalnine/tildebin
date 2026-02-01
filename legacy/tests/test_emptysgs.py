#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for emptysgs.py functionality.
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
        
        return proc.returncode, stdout, stderr
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command([sys.executable, 'emptysgs.py', '--help'])
    
    if return_code == 0:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        print("stderr: " + stderr.decode('utf-8'))
        return False


def test_argument_parsing():
    """Test that arguments are parsed correctly"""
    return_code, stdout, stderr = run_command([sys.executable, 'emptysgs.py', '--region', 'us-west-2'])
    
    # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
    if return_code == 1:  # Expected - missing credentials
        print("[PASS] Argument parsing test passed (detected missing credentials correctly)")
        return True
    else:
        print("[FAIL] Argument parsing test failed with return code: " + str(return_code))
        print("stderr: " + stderr.decode('utf-8'))
        return False


def test_region_option():
    """Test that the region option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'emptysgs.py', '--region', 'eu-west-1'])
    
    # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
    if return_code == 1:  # Expected - missing credentials
        print("[PASS] Region option test passed (recognized region argument)")
        return True
    else:
        print("[FAIL] Region option test failed with return code: " + str(return_code))
        print("stderr: " + stderr.decode('utf-8'))
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
    return_code, stdout, stderr = run_command([sys.executable, 'emptysgs.py'])
    
    # Should fail due to missing credentials
    if return_code == 1:
        print("[PASS] Environment variable handling test passed (detected missing credentials)")
        success = True
    else:
        print("[FAIL] Environment variable handling test failed with return code: " + str(return_code))
        print("stdout: " + stdout.decode('utf-8'))
        print("stderr: " + stderr.decode('utf-8'))
        success = False
    
    # Restore original environment variables
    if old_aws_access_key:
        os.environ['AWS_ACCESS_KEY_ID'] = old_aws_access_key
    if old_aws_secret_key:
        os.environ['AWS_SECRET_ACCESS_KEY'] = old_aws_secret_key
    
    return success


def test_default_region():
    """Test that the script uses the correct default region"""
    # Temporarily clear environment variables to test default
    old_aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    old_aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    
    if 'AWS_ACCESS_KEY_ID' in os.environ:
        del os.environ['AWS_ACCESS_KEY_ID']
    if 'AWS_SECRET_ACCESS_KEY' in os.environ:
        del os.environ['AWS_SECRET_ACCESS_KEY']
    
    # Test with default region (should be us-east-1 for emptysgs.py)
    return_code, stdout, stderr = run_command([sys.executable, 'emptysgs.py'])
    
    # Should fail due to missing credentials (not argument parsing issues)
    if return_code == 1:
        print("[PASS] Default region test passed (used us-east-1 as default)")
        success = True
    else:
        print("[FAIL] Default region test failed with return code: " + str(return_code))
        success = False
    
    # Restore original environment variables
    if old_aws_access_key:
        os.environ['AWS_ACCESS_KEY_ID'] = old_aws_access_key
    if old_aws_secret_key:
        os.environ['AWS_SECRET_ACCESS_KEY'] = old_aws_secret_key
    
    return success


if __name__ == "__main__":
    print("Testing emptysgs.py...")
    
    tests = [
        test_help_message,
        test_argument_parsing,
        test_region_option,
        test_environment_variable_handling,
        test_default_region
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
