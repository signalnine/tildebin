#!/usr/bin/env python3
"""
Test script for baremetal_tpm_health_monitor.py functionality.
Tests argument parsing and error handling without requiring TPM hardware.
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
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--help']
    )

    if return_code == 0 and 'tpm' in stdout.lower() and 'health' in stdout.lower():
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
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_plain():
    """Test that --format plain option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'plain', '--help']
    )

    if return_code == 0:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print(f"[FAIL] Format plain option test failed: {return_code}")
        return False


def test_format_option_json():
    """Test that --format json option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'json', '--help']
    )

    if return_code == 0:
        print("[PASS] Format json option test passed")
        return True
    else:
        print(f"[FAIL] Format json option test failed: {return_code}")
        return False


def test_format_option_table():
    """Test that --format table option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'table', '--help']
    )

    if return_code == 0:
        print("[PASS] Format table option test passed")
        return True
    else:
        print(f"[FAIL] Format table option test failed: {return_code}")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'invalid']
    )

    if return_code != 0:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option should fail")
        return False


def test_verbose_option():
    """Test that --verbose option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--verbose', '--help']
    )

    if return_code == 0 and 'verbose' in stdout.lower():
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed: {return_code}")
        return False


def test_warn_only_option():
    """Test that --warn-only option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--warn-only', '--help']
    )

    if return_code == 0 and 'warn' in stdout.lower():
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed: {return_code}")
        return False


def test_skip_selftest_option():
    """Test that --skip-selftest option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--skip-selftest', '--help']
    )

    if return_code == 0 and 'skip' in stdout.lower():
        print("[PASS] Skip-selftest option test passed")
        return True
    else:
        print(f"[FAIL] Skip-selftest option test failed: {return_code}")
        return False


def test_short_options():
    """Test short option forms."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '-v', '-w', '--help']
    )

    if return_code == 0:
        print("[PASS] Short options test passed")
        return True
    else:
        print(f"[FAIL] Short options test failed: {return_code}")
        return False


def test_execution_returns_valid_code():
    """Test that execution returns a valid exit code (0, 1, or 2)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--skip-selftest']
    )

    # Should return 0 (healthy), 1 (issues), or 2 (usage error)
    if return_code in [0, 1, 2]:
        print(f"[PASS] Execution returns valid exit code ({return_code})")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_plain_output_format():
    """Test plain output format contains expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'plain', '--skip-selftest']
    )

    # Output should mention TPM presence
    if 'TPM Present' in stdout or 'tpm' in stdout.lower():
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format missing expected content")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_structure():
    """Test JSON output structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'json', '--skip-selftest']
    )

    try:
        data = json.loads(stdout)

        # Check for expected keys
        if 'tpm_status' not in data or 'issues' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        tpm_status = data['tpm_status']
        expected_keys = ['tpm_present', 'device_paths']
        if not all(key in tpm_status for key in expected_keys):
            print("[FAIL] JSON tpm_status missing expected keys")
            print(f"  Keys: {list(tpm_status.keys())}")
            return False

        print("[PASS] JSON output structure test passed")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format contains header."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'table', '--skip-selftest']
    )

    # Table output should have a header
    if 'TPM HEALTH' in stdout.upper() or 'Property' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format missing header")
        print(f"  Output: {stdout[:300]}")
        return False


def test_no_tpm_handling():
    """Test handling when no TPM is present."""
    # Check if TPM exists on this system
    has_tpm = os.path.exists('/sys/class/tpm/tpm0') or os.path.exists('/dev/tpm0')

    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'json', '--skip-selftest']
    )

    try:
        data = json.loads(stdout)

        if not has_tpm:
            # If no TPM, should report as not present and have issues
            if not data['tpm_status']['tpm_present'] and len(data['issues']) > 0:
                print("[PASS] No TPM handling test passed (system has no TPM)")
                return True
            else:
                print("[FAIL] Should report TPM not present with issues")
                return False
        else:
            # If TPM exists, should report as present
            if data['tpm_status']['tpm_present']:
                print("[PASS] No TPM handling test passed (system has TPM)")
                return True
            else:
                print("[FAIL] TPM exists but not detected")
                return False

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed")
        return False


def test_verbose_with_json():
    """Test that verbose flag doesn't break JSON output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'json', '--verbose', '--skip-selftest']
    )

    try:
        data = json.loads(stdout)
        print("[PASS] Verbose with JSON test passed")
        return True
    except json.JSONDecodeError:
        print("[FAIL] Verbose flag breaks JSON output")
        return False


def test_warn_only_with_json():
    """Test that warn-only flag doesn't break JSON output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'json', '--warn-only', '--skip-selftest']
    )

    try:
        data = json.loads(stdout)
        print("[PASS] Warn-only with JSON test passed")
        return True
    except json.JSONDecodeError:
        print("[FAIL] Warn-only flag breaks JSON output")
        return False


def test_exit_codes_match_issues():
    """Test that exit codes match issue severity."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_tpm_health_monitor.py', '--format', 'json', '--skip-selftest']
    )

    try:
        data = json.loads(stdout)
        has_critical = any(i['severity'] == 'CRITICAL' for i in data['issues'])
        has_warning = any(i['severity'] == 'WARNING' for i in data['issues'])

        # If critical or warning issues, exit code should be 1
        if (has_critical or has_warning) and return_code != 1:
            print(f"[FAIL] Exit code should be 1 with issues, got {return_code}")
            return False

        # If no critical/warning issues and no TPM issues, exit code should be 0
        if not has_critical and not has_warning and return_code not in [0, 1]:
            print(f"[FAIL] Unexpected exit code {return_code}")
            return False

        print("[PASS] Exit codes match issues test passed")
        return True

    except json.JSONDecodeError:
        print("[FAIL] JSON parsing failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_tpm_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format_option,
        test_verbose_option,
        test_warn_only_option,
        test_skip_selftest_option,
        test_short_options,
        test_execution_returns_valid_code,
        test_plain_output_format,
        test_json_output_structure,
        test_table_output_format,
        test_no_tpm_handling,
        test_verbose_with_json,
        test_warn_only_with_json,
        test_exit_codes_match_issues,
    ]

    passed = 0
    skipped = 0
    failed = 0

    for test in tests:
        result = test()
        if result is True:
            passed += 1
        elif result is None:
            skipped += 1
        else:
            failed += 1

    total = len(tests)
    print()
    print(f"Test Results: {passed} passed, {failed} failed, {skipped} skipped out of {total}")

    if failed == 0:
        print("All applicable tests passed!")
        sys.exit(0)
    else:
        print(f"{failed} test(s) failed")
        sys.exit(1)
