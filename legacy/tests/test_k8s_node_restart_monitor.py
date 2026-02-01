#!/usr/bin/env python3
"""
Test script for k8s_node_restart_monitor.py functionality.
Tests argument parsing and error handling without requiring kubectl access.
"""

import subprocess
import sys
import json

def run_command(cmd_args):
    """Helper function to run a command and return result."""
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
    """Test that the help message works."""
    ret, out, err = run_command([sys.executable, 'k8s_node_restart_monitor.py', '--help'])

    if ret == 0 and 'Monitor Kubernetes node restart' in out:
        print("[PASS] Help message test")
        return True
    else:
        print("[FAIL] Help message test")
        print(f"  Return code: {ret}, Output: {out[:100]}")
        return False

def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'table', 'json']:
        ret, out, err = run_command([
            sys.executable, 'k8s_node_restart_monitor.py',
            '--format', fmt,
            '--help'
        ])
        if ret == 0 and 'Output format' in out:
            print(f"[PASS] --format {fmt} recognized")
        else:
            print(f"[FAIL] --format {fmt} not recognized")
            return False
    return True

def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    ret, out, err = run_command([
        sys.executable, 'k8s_node_restart_monitor.py',
        '--warn-only',
        '--help'
    ])
    if ret == 0 and 'Only show nodes with issues' in out:
        print("[PASS] --warn-only flag recognized")
        return True
    else:
        print("[FAIL] --warn-only flag not recognized")
        return False

def test_short_flags():
    """Test that short flags work."""
    ret, out, err = run_command([
        sys.executable, 'k8s_node_restart_monitor.py',
        '-f', 'json',
        '--help'
    ])
    if ret == 0:
        print("[PASS] Short flag -f recognized")
        return True
    else:
        print("[FAIL] Short flag -f not recognized")
        return False

def test_w_short_flag():
    """Test that -w short flag works."""
    ret, out, err = run_command([
        sys.executable, 'k8s_node_restart_monitor.py',
        '-w',
        '--help'
    ])
    if ret == 0:
        print("[PASS] Short flag -w recognized")
        return True
    else:
        print("[FAIL] Short flag -w not recognized")
        return False

def test_no_kubectl():
    """Test graceful handling when kubectl is not available."""
    ret, out, err = run_command([
        sys.executable, 'k8s_node_restart_monitor.py'
    ])

    # Should exit with code 2 (missing dependency) or 1 (kubectl error)
    if ret in [1, 2]:
        print("[PASS] Graceful handling when kubectl unavailable")
        return True
    else:
        print("[FAIL] Should exit with code 1 or 2 when kubectl unavailable")
        print(f"  Got return code: {ret}")
        return False

def test_invalid_format():
    """Test that invalid format is rejected."""
    ret, out, err = run_command([
        sys.executable, 'k8s_node_restart_monitor.py',
        '--format', 'invalid'
    ])

    if ret != 0 and ('invalid choice' in err or 'invalid' in err.lower()):
        print("[PASS] Invalid format rejected")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        print(f"  Return code: {ret}, Error: {err[:100]}")
        return False

def test_version_help_combinations():
    """Test various help message combinations."""
    ret, out, err = run_command([
        sys.executable, 'k8s_node_restart_monitor.py',
        '-h'
    ])

    if ret == 0 and 'usage:' in out.lower():
        print("[PASS] -h short help flag works")
        return True
    else:
        print("[FAIL] -h short help flag should work")
        return False

if __name__ == "__main__":
    print("Testing k8s_node_restart_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_options,
        test_warn_only_flag,
        test_short_flags,
        test_w_short_flag,
        test_version_help_combinations,
        test_invalid_format,
        test_no_kubectl,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
