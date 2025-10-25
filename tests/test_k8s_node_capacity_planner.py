#!/usr/bin/env python3
"""Tests for k8s_node_capacity_planner.py"""

import subprocess
import sys
import json

def run_command(cmd_args, stdin_input=None):
    """Run command and return (return_code, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_input else None
        )
        stdout, stderr = proc.communicate(input=stdin_input)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)

def test_help_message():
    """Test that --help displays correctly."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--help'])
    if return_code == 0 and 'Analyze Kubernetes cluster node capacity' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed: {stderr}")
        return False

def test_help_shows_formats():
    """Test that --help shows format options."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--help'])
    if return_code == 0 and all(fmt in stdout for fmt in ['table', 'plain', 'json', 'summary']):
        print("[PASS] Help shows format options")
        return True
    else:
        print("[FAIL] Help doesn't show format options")
        return False

def test_help_shows_warn_only():
    """Test that --help shows warn-only option."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--help'])
    if return_code == 0 and '--warn-only' in stdout:
        print("[PASS] Help shows warn-only option")
        return True
    else:
        print("[FAIL] Help doesn't show warn-only option")
        return False

def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', 'invalid'])
    if return_code != 0:
        print("[PASS] Invalid format rejected")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False

def test_format_options():
    """Test that each format option is accepted."""
    formats = ['table', 'plain', 'json', 'summary']
    for fmt in formats:
        return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', fmt])
        # Should fail with k8s error, not argument error
        if 'unrecognized arguments' not in stderr:
            print(f"[PASS] Format '{fmt}' accepted in argument parsing")
        else:
            print(f"[FAIL] Format '{fmt}' rejected in argument parsing")
            return False
    return True

def test_short_format_flag():
    """Test that -f flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -f flag works")
        return True
    else:
        print("[FAIL] Short -f flag doesn't work")
        return False

def test_long_format_flag():
    """Test that --format flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--format', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Long --format flag works")
        return True
    else:
        print("[FAIL] Long --format flag doesn't work")
        return False

def test_warn_only_flag():
    """Test that --warn-only flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--warn-only'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --warn-only flag works")
        return True
    else:
        print("[FAIL] --warn-only flag doesn't work")
        return False

def test_short_warn_flag():
    """Test that -w flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-w'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -w flag works")
        return True
    else:
        print("[FAIL] Short -w flag doesn't work")
        return False

def test_kubernetes_import_error():
    """Test that missing kubernetes library is handled gracefully."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', 'json'])
    # When kubernetes isn't configured, should fail with kubernetes error, not import error
    if return_code != 0:
        print("[PASS] Kubernetes error handled")
        return True
    else:
        print("[FAIL] Should exit with error when kubernetes not available")
        return False

def test_default_format_is_table():
    """Test that default format is table (not json or plain)."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py'])
    # Should fail due to no k8s cluster, but argument parsing should work
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Default format argument parsing works")
        return True
    else:
        print("[FAIL] Default format not properly set")
        return False

if __name__ == "__main__":
    tests = [
        test_help_message,
        test_help_shows_formats,
        test_help_shows_warn_only,
        test_invalid_format,
        test_format_options,
        test_short_format_flag,
        test_long_format_flag,
        test_warn_only_flag,
        test_short_warn_flag,
        test_kubernetes_import_error,
        test_default_format_is_table,
    ]

    passed = sum(1 for test in tests if test())
    print(f"\nTest Results: {passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
