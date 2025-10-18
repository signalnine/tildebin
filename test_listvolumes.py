#!/usr/bin/env python3
"""
Test script for listvolumes.py functionality.
Since the script relies on AWS credentials and API calls, this test will focus on:
1. Argument parsing
2. Output formatting
3. Error handling
4. Credential handling
"""

import subprocess
import sys
import os

def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(cmd_args, 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        stdout, stderr = proc.communicate()
        
        return proc.returncode, stdout, stderr
    except Exception as e:
        return -1, "", str(e)

def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command([sys.executable, 'listvolumes.py', '--help'])
    
    if return_code == 0 and '--filters' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code:", return_code)
        print("stdout:", stdout[:200])
        return False

def test_argument_parsing():
    """Test that arguments are parsed correctly"""
    return_code, stdout, stderr = run_command([sys.executable, 'listvolumes.py', '--region', 'us-east-1'])
    
    # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
    if return_code == 1:  # Expected - missing credentials
        print("[PASS] Argument parsing test passed (detected missing credentials correctly)")
        return True
    else:
        print("[FAIL] Argument parsing test failed with return code:", return_code)
        print("stderr:", stderr)
        return False

def test_format_option():
    """Test that the format option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'listvolumes.py', '--format', 'table'])
    
    # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
    if return_code == 1:  # Expected - missing credentials
        print("[PASS] Format option test passed (recognized format argument)")
        return True
    else:
        print("[FAIL] Format option test failed with return code:", return_code)
        print("stderr:", stderr)
        return False

def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command([sys.executable, 'listvolumes.py', '--format', 'invalid'])
    
    # Should fail with argument error
    if return_code != 0:
        print("[PASS] Invalid format option test passed (rejected invalid format)")
        return True
    else:
        print("[FAIL] Invalid format option test failed - should have failed with invalid choice")
        return False

def test_filters_option():
    """Test that the filters option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'listvolumes.py', '--filters', 'status=available'])
    
    # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
    if return_code == 1:  # Expected - missing credentials
        print("[PASS] Filters option test passed (recognized filters argument)")
        return True
    else:
        print("[FAIL] Filters option test failed with return code:", return_code)
        print("stderr:", stderr)
        return False

def test_boto3_flag():
    """Test that the boto3 flag is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'listvolumes.py', '--boto3'])
    
    # The script should return 1 due to missing AWS credentials or potentially due to missing boto3
    if return_code != 2:  # 2 would be argument parsing error
        print("[PASS] Boto3 flag test passed (recognized boto3 argument)")
        return True
    else:
        print("[FAIL] Boto3 flag test failed with return code:", return_code)
        print("stderr:", stderr)
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
    return_code, stdout, stderr = run_command([sys.executable, 'listvolumes.py'])
    
    # Should fail due to missing credentials
    if return_code == 1:
        print("[PASS] Environment variable handling test passed (detected missing credentials)")
        success = True
    else:
        print("[FAIL] Environment variable handling test failed with return code:", return_code)
        print("stdout:", stdout)
        print("stderr:", stderr)
        success = False
    
    # Restore original environment variables
    if old_aws_access_key:
        os.environ['AWS_ACCESS_KEY_ID'] = old_aws_access_key
    if old_aws_secret_key:
        os.environ['AWS_SECRET_ACCESS_KEY'] = old_aws_secret_key
    
    return success

if __name__ == "__main__":
    print("Testing listvolumes.py...")
    
    tests = [
        test_help_message,
        test_argument_parsing,
        test_format_option,
        test_invalid_format_option,
        test_filters_option,
        test_boto3_flag,
        test_environment_variable_handling
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\\nTest Results: {}/{} tests passed".format(passed, total))
    
    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)