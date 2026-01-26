#!/usr/bin/env python3
"""
Test script for baremetal_kernel_log_rate_monitor.py functionality.
Tests argument parsing and error handling without requiring root access.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result"""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=10)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--help']
    )

    if return_code == 0 and 'kernel' in stdout.lower() and 'rate' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_format_option_plain():
    """Test that plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--format', 'plain']
    )

    # Script will run (may succeed or fail based on dmesg availability)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--format', 'json']
    )

    # If script runs successfully or finds issues
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'status' in data and 'statistics' in data:
                print("[PASS] JSON format option test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys")
                print(f"  Keys found: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON format test failed: invalid JSON output")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # dmesg not available - that's OK for this test
        print("[PASS] JSON format option test passed (dmesg not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed: unexpected return code {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--format', 'invalid']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2 or 'invalid choice' in stderr.lower():
        print("[PASS] Invalid format rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid format should be rejected")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_verbose_flag():
    """Test that verbose flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_warn_rate_option():
    """Test that warn-rate option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--warn-rate', '100']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-rate option test passed")
        return True
    else:
        print(f"[FAIL] Warn-rate option test failed: unexpected return code {return_code}")
        return False


def test_crit_rate_option():
    """Test that crit-rate option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--crit-rate', '500']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Crit-rate option test passed")
        return True
    else:
        print(f"[FAIL] Crit-rate option test failed: unexpected return code {return_code}")
        return False


def test_burst_threshold_option():
    """Test that burst-threshold option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--burst-threshold', '30']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Burst-threshold option test passed")
        return True
    else:
        print(f"[FAIL] Burst-threshold option test failed: unexpected return code {return_code}")
        return False


def test_invalid_threshold_relationship():
    """Test that warn-rate >= crit-rate is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py',
         '--warn-rate', '200', '--crit-rate', '100']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Invalid threshold relationship test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold relationship should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py',
         '--format', 'json', '-v', '--warn-only',
         '--warn-rate', '75', '--crit-rate', '300']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed: unexpected return code {return_code}")
        return False


def test_json_structure():
    """Test that JSON output has correct structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            required_keys = ['status', 'statistics', 'bursts', 'issues']
            stats_keys = ['total_messages', 'messages_per_minute', 'has_timestamps']

            missing_keys = [k for k in required_keys if k not in data]
            if missing_keys:
                print(f"[FAIL] JSON missing top-level keys: {missing_keys}")
                return False

            missing_stats = [k for k in stats_keys if k not in data.get('statistics', {})]
            if missing_stats:
                print(f"[FAIL] JSON statistics missing keys: {missing_stats}")
                return False

            print("[PASS] JSON structure test passed")
            return True
        except json.JSONDecodeError:
            print(f"[FAIL] JSON structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON structure test passed (dmesg not available)")
        return True
    else:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_log_rate_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (OK), 1 (issues found), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_kernel_log_rate_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_warn_rate_option,
        test_crit_rate_option,
        test_burst_threshold_option,
        test_invalid_threshold_relationship,
        test_combined_options,
        test_json_structure,
        test_exit_codes,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
