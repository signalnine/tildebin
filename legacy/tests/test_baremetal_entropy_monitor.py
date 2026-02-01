#!/usr/bin/env python3
"""
Test script for baremetal_entropy_monitor.py functionality.
Tests argument parsing and output formats without requiring specific entropy conditions.
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
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--help']
    )

    if return_code == 0 and 'entropy' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py']
    )

    # Should succeed (exit 0 or 1 depending on entropy level)
    if return_code in [0, 1] and 'Entropy:' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'entropy' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify entropy data structure
        entropy = data['entropy']
        required_keys = ['available', 'pool_size', 'percent',
                        'read_wakeup_threshold', 'write_wakeup_threshold']
        if not all(key in entropy for key in required_keys):
            print("[FAIL] JSON entropy data missing required keys")
            print(f"  Entropy keys: {list(entropy.keys())}")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'ENTROPY POOL STATUS' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--verbose']
    )

    # Should succeed and contain additional details like RNG info
    if return_code in [0, 1] and ('Read wakeup threshold' in stdout or
                                   'Hardware RNG' in stdout):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on entropy state)
    # Output might be empty if no warnings
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_custom_thresholds():
    """Test custom threshold arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--warn', '512', '--crit', '128']
    )

    # Should succeed with custom thresholds
    if return_code in [0, 1]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_negative():
    """Test that negative threshold values are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--warn', '-100']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (negative) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (negative) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_crit_ge_warn():
    """Test that crit >= warn is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--warn', '100', '--crit', '200']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold (crit >= warn) test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold (crit >= warn) test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_verbose_includes_rng():
    """Test JSON verbose output includes RNG data."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--format', 'json', '--verbose']
    )

    try:
        data = json.loads(stdout)

        # Verbose should include rng information
        if 'rng' not in data:
            print("[FAIL] JSON verbose missing 'rng' data")
            return False

        rng = data['rng']
        required_keys = ['hw_available', 'hw_name', 'rngd_running', 'haveged_running']
        if not all(key in rng for key in required_keys):
            print("[FAIL] JSON rng data missing required keys")
            print(f"  RNG keys: {list(rng.keys())}")
            return False

        print("[PASS] JSON verbose RNG data test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON verbose parsing failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_entropy_values_are_numeric():
    """Test that entropy values in JSON are numeric."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_entropy_monitor.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        entropy = data['entropy']

        # Check that values are numeric
        if not isinstance(entropy['available'], int):
            print("[FAIL] entropy.available is not an integer")
            return False
        if not isinstance(entropy['pool_size'], int):
            print("[FAIL] entropy.pool_size is not an integer")
            return False
        if not isinstance(entropy['percent'], (int, float)):
            print("[FAIL] entropy.percent is not numeric")
            return False

        print("[PASS] Entropy values are numeric test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Entropy values test failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_entropy_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_custom_thresholds,
        test_invalid_threshold_negative,
        test_invalid_threshold_crit_ge_warn,
        test_json_verbose_includes_rng,
        test_exit_codes,
        test_entropy_values_are_numeric,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
