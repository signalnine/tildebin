#!/usr/bin/env python3
"""
Test script for baremetal_workqueue_monitor.py functionality.

Tests argument parsing, output formats, and error handling without requiring
root access or specific workqueue states.
"""

import subprocess
import sys
import json
import os


def run_command(cmd_args):
    """Helper function to run a command and return result."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works and contains expected content."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--help']
    )

    if return_code != 0:
        print(f"[FAIL] Help message test failed - exit code {return_code}")
        return False

    expected_terms = ['workqueue', 'kworker', 'format', 'verbose', 'warn-only']
    missing = [term for term in expected_terms if term not in stdout.lower()]

    if missing:
        print(f"[FAIL] Help message missing expected terms: {missing}")
        return False

    print("[PASS] Help message test passed")
    return True


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--invalid-flag']
    )

    if return_code == 0:
        print("[FAIL] Invalid arguments should fail")
        return False

    print("[PASS] Invalid arguments test passed")
    return True


def test_plain_format():
    """Test plain output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--format', 'plain']
    )

    # Script should run (exit 0 or 1 for issues, but not 2)
    if return_code == 2:
        print(f"[FAIL] Plain format test failed - exit code 2 (usage error)")
        print(f"  Stderr: {stderr[:200]}")
        return False

    # Should contain kworker info
    if 'kworker' not in stdout.lower() and 'workqueue' not in stdout.lower():
        print("[FAIL] Plain output should mention kworker or workqueue")
        print(f"  Output: {stdout[:200]}")
        return False

    print("[PASS] Plain format test passed")
    return True


def test_json_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print(f"[FAIL] JSON format test failed - exit code 2")
        return False

    try:
        data = json.loads(stdout)
        # Check for expected keys
        if 'kworker_stats' not in data:
            print("[FAIL] JSON output missing 'kworker_stats' key")
            return False
        if 'issues' not in data:
            print("[FAIL] JSON output missing 'issues' key")
            return False

        # Validate kworker_stats structure
        stats = data['kworker_stats']
        expected_keys = ['total_kworkers', 'running', 'sleeping', 'uninterruptible']
        for key in expected_keys:
            if key not in stats:
                print(f"[FAIL] kworker_stats missing '{key}' key")
                return False

        print("[PASS] JSON format test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--format', 'table']
    )

    if return_code == 2:
        print(f"[FAIL] Table format test failed - exit code 2")
        return False

    # Table output should have headers and separators
    if '=' not in stdout and '-' not in stdout:
        print("[FAIL] Table output should contain formatting characters")
        return False

    print("[PASS] Table format test passed")
    return True


def test_verbose_flag():
    """Test verbose output mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--verbose']
    )

    if return_code == 2:
        print(f"[FAIL] Verbose flag test failed - exit code 2")
        return False

    # Verbose output should be longer than non-verbose
    return_code_normal, stdout_normal, _ = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py']
    )

    # Verbose should have more content (at least on systems with workqueues)
    # If /sys/bus/workqueue/devices exists, verbose will show more
    if os.path.exists('/sys/bus/workqueue/devices'):
        if len(stdout) < len(stdout_normal):
            print("[FAIL] Verbose output should be at least as long as normal output")
            return False

    print("[PASS] Verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test warn-only output mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--warn-only']
    )

    if return_code == 2:
        print(f"[FAIL] Warn-only flag test failed - exit code 2")
        return False

    # Warn-only should not show INFO messages or normal status
    # But it should still work
    print("[PASS] Warn-only flag test passed")
    return True


def test_json_verbose():
    """Test verbose JSON output contains workqueues."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--format', 'json', '--verbose']
    )

    if return_code == 2:
        print(f"[FAIL] JSON verbose test failed - exit code 2")
        return False

    try:
        data = json.loads(stdout)
        # Verbose JSON should include workqueues list
        if 'workqueues' not in data:
            print("[FAIL] Verbose JSON should include 'workqueues' key")
            return False
        print("[PASS] JSON verbose test passed")
        return True
    except json.JSONDecodeError:
        print("[FAIL] JSON verbose parsing failed")
        return False


def test_threshold_validation():
    """Test that invalid threshold combinations are rejected."""
    # Warning threshold >= critical should fail
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py',
         '--uninterruptible-warn', '10', '--uninterruptible-crit', '5']
    )

    if return_code != 2:
        print("[FAIL] Invalid threshold combination should return exit code 2")
        return False

    if 'must be less than' not in stderr.lower():
        print("[FAIL] Should indicate threshold ordering error")
        return False

    print("[PASS] Threshold validation test passed")
    return True


def test_negative_threshold():
    """Test that negative thresholds are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py',
         '--uninterruptible-warn', '-1']
    )

    if return_code != 2:
        print("[FAIL] Negative threshold should return exit code 2")
        return False

    print("[PASS] Negative threshold test passed")
    return True


def test_custom_thresholds():
    """Test that custom thresholds are accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py',
         '--uninterruptible-warn', '3', '--uninterruptible-crit', '8',
         '--kworker-count-warn', '1000']
    )

    if return_code == 2:
        print(f"[FAIL] Custom thresholds should be accepted")
        print(f"  Stderr: {stderr}")
        return False

    print("[PASS] Custom thresholds test passed")
    return True


def test_proc_availability():
    """Test that script handles /proc availability correctly."""
    # This test just verifies the script runs - it should always
    # have /proc available on Linux
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py']
    )

    # Should not fail with exit code 2 on a Linux system with /proc
    if os.path.exists('/proc') and return_code == 2:
        # Check if it's a legitimate error (not missing /proc)
        if '/proc' in stderr and 'not available' in stderr:
            print("[FAIL] /proc should be available on this system")
            return False

    print("[PASS] /proc availability test passed")
    return True


def test_kworker_stats_structure():
    """Test that kworker stats contain expected numeric values."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_workqueue_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[FAIL] Script should not fail with usage error")
        return False

    try:
        data = json.loads(stdout)
        stats = data.get('kworker_stats', {})

        # All stats should be non-negative integers
        for key in ['total_kworkers', 'running', 'sleeping', 'uninterruptible']:
            value = stats.get(key)
            if value is None:
                print(f"[FAIL] Missing kworker stat: {key}")
                return False
            if not isinstance(value, int) or value < 0:
                print(f"[FAIL] Invalid kworker stat {key}: {value}")
                return False

        print("[PASS] kworker stats structure test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_workqueue_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_format,
        test_json_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_json_verbose,
        test_threshold_validation,
        test_negative_threshold,
        test_custom_thresholds,
        test_proc_availability,
        test_kworker_stats_structure,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__} raised exception: {e}")
            failed += 1

    print("=" * 60)
    print(f"Test Results: {passed}/{len(tests)} tests passed")

    if failed > 0:
        print(f"  {failed} tests failed")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)
