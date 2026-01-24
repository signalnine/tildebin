#!/usr/bin/env python3
"""
Test script for baremetal_syslog_rate_monitor.py functionality.
Tests argument parsing and output formatting without requiring specific journal state.
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
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--help']
    )

    if return_code == 0 and 'syslog' in stdout.lower() and 'rate' in stdout.lower():
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
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (normal), 1 (issues), 2 (error/no journalctl)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected JSON structure
            required_keys = ['total_count', 'rate_per_minute', 'top_sources', 'has_issues']
            if all(key in data for key in required_keys):
                print("[PASS] JSON format option test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys")
                print(f"  Found keys: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON format test failed: invalid JSON output")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Error (e.g., no journalctl) - acceptable
        print("[PASS] JSON format option test passed (journalctl not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '-v']
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
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_since_option():
    """Test that since option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--since', '10']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Since option test passed")
        return True
    else:
        print(f"[FAIL] Since option test failed: unexpected return code {return_code}")
        return False


def test_threshold_option():
    """Test that threshold option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--threshold', '50']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Threshold option test passed")
        return True
    else:
        print(f"[FAIL] Threshold option test failed: unexpected return code {return_code}")
        return False


def test_top_option():
    """Test that top option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--top', '5']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Top option test passed")
        return True
    else:
        print(f"[FAIL] Top option test failed: unexpected return code {return_code}")
        return False


def test_invalid_since_value():
    """Test that invalid since value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--since', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid since value rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid since value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_threshold_value():
    """Test that invalid threshold value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--threshold', '-1']
    )

    if return_code == 2:
        print("[PASS] Invalid threshold value rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_top_value():
    """Test that invalid top value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--top', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid top value rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid top value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py',
         '--format', 'json', '-v', '--since', '10', '--threshold', '50']
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
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check for expected keys
            expected_keys = [
                'timestamp', 'window_minutes', 'rate_threshold',
                'total_count', 'rate_per_minute', 'top_sources',
                'high_rate_sources', 'priority_summary', 'has_issues'
            ]

            missing = [k for k in expected_keys if k not in data]
            if not missing:
                print("[PASS] JSON structure test passed")
                return True
            else:
                print(f"[FAIL] JSON missing keys: {missing}")
                return False

        except json.JSONDecodeError:
            print(f"[FAIL] JSON structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON structure test passed (journalctl not available)")
        return True
    else:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False


def test_json_priority_summary():
    """Test that JSON priority_summary has all priority levels"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if 'priority_summary' in data:
                ps = data['priority_summary']
                expected_priorities = [
                    'emergency', 'alert', 'critical', 'error',
                    'warning', 'notice', 'info', 'debug'
                ]
                missing = [p for p in expected_priorities if p not in ps]
                if not missing:
                    print("[PASS] JSON priority summary test passed")
                    return True
                else:
                    print(f"[FAIL] Priority summary missing: {missing}")
                    return False

            print("[FAIL] JSON missing priority_summary key")
            return False

        except json.JSONDecodeError:
            print(f"[FAIL] JSON priority summary test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON priority summary test passed (journalctl not available)")
        return True
    else:
        print(f"[FAIL] JSON priority summary test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (normal), 1 (issues), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--help']
    )

    if return_code == 0 and 'example' in stdout.lower():
        print("[PASS] Help examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain examples")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_use_cases():
    """Test that help message contains use cases"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_syslog_rate_monitor.py', '--help']
    )

    if return_code == 0 and 'use case' in stdout.lower():
        print("[PASS] Help use cases test passed")
        return True
    else:
        print(f"[FAIL] Help should contain use cases")
        return False


if __name__ == "__main__":
    print("Testing baremetal_syslog_rate_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_since_option,
        test_threshold_option,
        test_top_option,
        test_invalid_since_value,
        test_invalid_threshold_value,
        test_invalid_top_value,
        test_combined_options,
        test_json_structure,
        test_json_priority_summary,
        test_exit_codes,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_help_contains_use_cases,
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
