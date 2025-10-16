#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script for listec2hosts.py functionality.
Since the script relies on AWS credentials and API calls, this test will focus on:
1. Argument parsing
2. Output formatting
3. Error handling
"""

import subprocess
import sys
import os

def test_help_message():
    """Test that the help message works"""
    try:
        # In Python 2, we need to use Popen instead of run
        proc = subprocess.Popen(['python2', 'listec2hosts.py', '--help'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()  # No timeout in Python 2
        
        # Should not fail even without AWS credentials
        if proc.returncode == 0:
            print("[PASS] Help message test passed")
            return True
        else:
            print("[FAIL] Help message test failed - return code: " + str(proc.returncode))
            return False
    except Exception as e:
        print("[FAIL] Help message test failed with error: " + str(e))
        return False

def test_argument_parsing():
    """Test that arguments are parsed correctly"""
    try:
        proc = subprocess.Popen(['python2', 'listec2hosts.py', '--all'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        
        # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
        if proc.returncode == 1:  # Expected - missing credentials
            print("[PASS] Argument parsing test passed (detected missing credentials correctly)")
            return True
        else:
            print("[FAIL] Argument parsing test failed with return code: " + str(proc.returncode))
            print("stderr: " + stderr)
            return False
    except Exception as e:
        print("[FAIL] Argument parsing test failed with error: " + str(e))
        return False

def test_format_option():
    """Test that the format option is recognized"""
    try:
        proc = subprocess.Popen(['python2', 'listec2hosts.py', '--format', 'table'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        
        # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
        if proc.returncode == 1:  # Expected - missing credentials
            print("[PASS] Format option test passed (recognized format argument)")
            return True
        else:
            print("[FAIL] Format option test failed with return code: " + str(proc.returncode))
            print("stderr: " + stderr)
            return False
    except Exception as e:
        print("[FAIL] Format option test failed with error: " + str(e))
        return False

def test_region_option():
    """Test that the region option is recognized"""
    try:
        proc = subprocess.Popen(['python2', 'listec2hosts.py', '--region', 'us-east-1'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        
        # The script should return 1 due to missing AWS credentials, not 2 (syntax error)
        if proc.returncode == 1:  # Expected - missing credentials
            print("[PASS] Region option test passed (recognized region argument)")
            return True
        else:
            print("[FAIL] Region option test failed with return code: " + str(proc.returncode))
            print("stderr: " + stderr)
            return False
    except Exception as e:
        print("[FAIL] Region option test failed with error: " + str(e))
        return False

if __name__ == "__main__":
    print("Testing listec2hosts.py...")
    
    tests = [
        test_help_message,
        test_argument_parsing,
        test_format_option,
        test_region_option
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