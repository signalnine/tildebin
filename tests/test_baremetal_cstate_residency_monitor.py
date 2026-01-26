#!/usr/bin/env python3
"""
Test script for baremetal_cstate_residency_monitor.py functionality.
Tests argument parsing and error handling without requiring cpuidle support.
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
        [sys.executable, 'baremetal_cstate_residency_monitor.py', '--help']
    )

    if return_code == 0 and 'c-state' in stdout.lower():
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
        [sys.executable, 'baremetal_cstate_residency_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_options():
    """Test that format options are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_cstate_residency_monitor.py', '--format', fmt]
        )

        # Script may exit with 2 (no cpuidle) but should recognize the format option
        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Format option '{fmt}' not recognized")
            return False

    print("[PASS] Format options test passed")
    return True


def test_verbose_option():
    """Test that verbose option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py', '-v']
    )

    # Should recognize the option
    if 'unrecognized arguments' in stderr.lower() and '-v' in stderr:
        print("[FAIL] Verbose option not recognized")
        print(f"  stderr: {stderr[:200]}")
        return False

    print("[PASS] Verbose option test passed")
    return True


def test_warn_only_option():
    """Test that warn-only option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py', '-w']
    )

    # Should recognize the option
    if 'unrecognized arguments' in stderr.lower() and '-w' in stderr:
        print("[FAIL] Warn-only option not recognized")
        print(f"  stderr: {stderr[:200]}")
        return False

    print("[PASS] Warn-only option test passed")
    return True


def test_min_deep_residency_option():
    """Test that min-deep-residency option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py',
         '--min-deep-residency', '5']
    )

    # Should recognize the option
    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] min-deep-residency option not recognized")
        print(f"  stderr: {stderr[:200]}")
        return False

    print("[PASS] min-deep-residency option test passed")
    return True


def test_invalid_min_deep_residency():
    """Test that invalid min-deep-residency value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py',
         '--min-deep-residency', 'invalid']
    )

    # Should fail with invalid value
    if return_code != 0 and 'invalid' in stderr.lower():
        print("[PASS] Invalid min-deep-residency test passed")
        return True
    else:
        print("[FAIL] Invalid min-deep-residency should fail")
        print(f"  Return code: {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False


def test_json_output_structure():
    """Test JSON output format structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py', '--format', 'json']
    )

    # If cpuidle is available, output should be valid JSON
    if return_code == 0 or return_code == 1:
        try:
            data = json.loads(stdout)
            # Check expected top-level keys
            required_keys = ['driver', 'governor', 'cpu_count', 'cpus', 'issues']
            for key in required_keys:
                if key not in data:
                    print(f"[FAIL] JSON output missing key: {key}")
                    return False

            # Check CPU data structure if available
            if data['cpus']:
                cpu = data['cpus'][0]
                if 'cpu' not in cpu or 'states' not in cpu:
                    print("[FAIL] JSON CPU data missing required fields")
                    return False

            print("[PASS] JSON output structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False

    # If no cpuidle support (exit code 2), that's acceptable
    if return_code == 2:
        print("[PASS] JSON output structure test passed (no cpuidle available)")
        return True

    print(f"[FAIL] Unexpected return code: {return_code}")
    return False


def test_no_cpuidle_error():
    """Test graceful handling when cpuidle is not available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py']
    )

    # On systems without cpuidle, should exit with 2 and helpful message
    if return_code == 2:
        if 'cpuidle' in stderr.lower() or 'cpu idle' in stderr.lower():
            print("[PASS] No cpuidle error handling test passed")
            return True
        else:
            print("[FAIL] No cpuidle error message not helpful")
            print(f"  stderr: {stderr[:200]}")
            return False
    elif return_code in (0, 1):
        # System has cpuidle support
        print("[PASS] No cpuidle error handling test passed (cpuidle available)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        print(f"  stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combination of multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py',
         '--format', 'json', '-v', '-w', '--min-deep-residency', '15']
    )

    # Should recognize all options
    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Combined options test failed")
        print(f"  stderr: {stderr[:200]}")
        return False

    print("[PASS] Combined options test passed")
    return True


def test_help_contains_examples():
    """Test that help message contains usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py', '--help']
    )

    if return_code == 0 and 'example' in stdout.lower():
        print("[PASS] Help contains examples test passed")
        return True
    else:
        print("[FAIL] Help should contain examples")
        print(f"  Output: {stdout[:300]}")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_cstate_residency_monitor.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print("[FAIL] Help should document exit codes")
        print(f"  Output: {stdout[:300]}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_cstate_residency_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_options,
        test_verbose_option,
        test_warn_only_option,
        test_min_deep_residency_option,
        test_invalid_min_deep_residency,
        test_json_output_structure,
        test_no_cpuidle_error,
        test_combined_options,
        test_help_contains_examples,
        test_help_contains_exit_codes,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
