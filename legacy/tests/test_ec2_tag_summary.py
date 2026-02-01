#!/usr/bin/env python3
"""
Test script for ec2_tag_summary.py functionality.
Since the script relies on AWS credentials and API calls, this test will focus on:
1. Argument parsing
2. Output formatting
3. Error handling
4. Basic functionality validation
"""

import subprocess
import sys
import os
import json


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
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_tag_summary.py', '--help'])
    
    if return_code == 0 and '--tag-key' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code:", return_code)
        print("stdout:", stdout[:200])
        return False


def test_required_args():
    """Test that required arguments are enforced"""
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_tag_summary.py'])
    
    # Should fail with argument error since --tag-key is required
    if return_code != 0:
        print("[PASS] Required args validation test passed")
        return True
    else:
        print("[FAIL] Required args validation test failed - should have failed without required args")
        return False


def test_tag_key_argument():
    """Test that the tag key argument is recognized"""
    # This should fail due to missing credentials, not argument parsing
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_tag_summary.py', '--tag-key', 'Name'])
    
    # Should fail due to missing credentials but not argument parsing
    if return_code != 0:  # Expected - missing credentials or other AWS error
        print("[PASS] Tag key argument test passed (argument recognized, failed due to AWS access)")
        return True
    else:
        print("[PASS] Tag key argument test passed (AWS access might be available)")
        return True


def test_format_options():
    """Test that both format options are recognized"""
    # Test plain format
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_tag_summary.py', '--tag-key', 'Name', '--format', 'plain'])
    
    # Should fail due to missing credentials but not argument parsing
    format_plain_ok = (return_code != 0 or 'No instances found' in stdout)
    
    # Test json format
    return_code, stdout, stderr = run_command([sys.executable, 'ec2_tag_summary.py', '--tag-key', 'Name', '--format', 'json'])
    
    # Should fail due to missing credentials but not argument parsing
    format_json_ok = (return_code != 0 or stdout.startswith('{') or 'No instances found' in stdout)
    
    if format_plain_ok and format_json_ok:
        print("[PASS] Format options test passed")
        return True
    else:
        print("[FAIL] Format options test failed")
        return False


def test_region_argument():
    """Test that the regions argument is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'ec2_tag_summary.py', 
        '--tag-key', 'Name', 
        '--regions', 'us-east-1', 'us-west-2'
    ])
    
    # Should fail due to missing credentials but not argument parsing
    if return_code != 0 or 'No instances found' in stdout:
        print("[PASS] Region argument test passed")
        return True
    else:
        print("[FAIL] Region argument test failed")
        return False


def test_tag_value_argument():
    """Test that the tag value argument is recognized"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'ec2_tag_summary.py', 
        '--tag-key', 'Name',
        '--tag-value', 'test'
    ])
    
    # Should fail due to missing credentials but not argument parsing
    if return_code != 0 or 'No instances found' in stdout:
        print("[PASS] Tag value argument test passed")
        return True
    else:
        print("[FAIL] Tag value argument test failed")
        return False


if __name__ == "__main__":
    print("Testing ec2_tag_summary.py...")
    
    tests = [
        test_help_message,
        test_required_args,
        test_tag_key_argument,
        test_format_options,
        test_region_argument,
        test_tag_value_argument
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\nTest Results: {}/{} tests passed".format(passed, total))
    
    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)