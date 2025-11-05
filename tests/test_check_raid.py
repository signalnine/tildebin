#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for check_raid.py functionality.
Tests argument parsing and error handling without requiring actual RAID arrays.
"""

import subprocess
import sys


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
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--help'])
    assert return_code == 0, f"Help command failed with return code: {return_code}"
    assert 'Check status' in stdout, "Expected 'Check status' in help output"


def test_type_option_all():
    """Test that the type option accepts 'all'"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'all'])
    # Should not fail at argument parsing level
    assert return_code in [0, 1], f"Type option 'all' failed with unexpected return code: {return_code}, stderr: {stderr}"


def test_type_option_software():
    """Test that the type option accepts 'software'"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'software'])
    # Should not fail at argument parsing level
    assert return_code in [0, 1], f"Type option 'software' failed with unexpected return code: {return_code}, stderr: {stderr}"


def test_type_option_hardware():
    """Test that the type option accepts 'hardware'"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'hardware'])
    # Should not fail at argument parsing level
    assert return_code in [0, 1], f"Type option 'hardware' failed with unexpected return code: {return_code}, stderr: {stderr}"


def test_invalid_type():
    """Test that invalid type option is rejected"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--type', 'invalid'])
    # Should fail with argument error
    assert return_code != 0, "Invalid type should have been rejected"
    assert 'invalid choice' in stderr or 'invalid choice' in stdout, "Expected 'invalid choice' error message"


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '-v'])
    # Should not fail at argument parsing level
    assert return_code in [0, 1], f"Verbose option failed with unexpected return code: {return_code}, stderr: {stderr}"


def test_format_option():
    """Test that the format option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--format', 'json'])
    # Should not fail at argument parsing level
    assert return_code in [0, 1], f"Format option failed with unexpected return code: {return_code}, stderr: {stderr}"


def test_warn_only_option():
    """Test that the warn-only option is recognized"""
    return_code, stdout, stderr = run_command([sys.executable, 'check_raid.py', '--warn-only'])
    # Should not fail at argument parsing level
    assert return_code in [0, 1], f"Warn-only option failed with unexpected return code: {return_code}, stderr: {stderr}"


def test_combined_options():
    """Test that multiple options can be combined"""
    return_code, stdout, stderr = run_command([
        sys.executable, 'check_raid.py',
        '--type', 'software',
        '-v',
        '--format', 'json'
    ])
    # Should not fail at argument parsing level
    assert return_code in [0, 1], f"Combined options failed with unexpected return code: {return_code}, stderr: {stderr}"
