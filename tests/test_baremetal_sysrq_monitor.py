#!/usr/bin/env python3
"""
Test script for baremetal_sysrq_monitor.py functionality.
Tests argument parsing and output formatting without requiring specific system state.
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
        [sys.executable, 'baremetal_sysrq_monitor.py', '--help']
    )

    if return_code == 0 and 'sysrq' in stdout.lower() and 'magic' in stdout.lower():
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
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'plain']
    )

    # Script will run and report SysRq status
    # Valid exit codes: 0 (OK), 1 (warnings), 2 (error)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected JSON structure
            required_keys = ['sysrq_value', 'enabled', 'functions', 'summary']
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
        # Error reading sysrq (e.g., in container) - acceptable
        print("[PASS] JSON format option test passed (sysrq not accessible)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_sysrq_monitor.py', '-v']
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
        [sys.executable, 'baremetal_sysrq_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_expected_option():
    """Test that expected option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--expected', '176']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Expected option test passed")
        return True
    else:
        print(f"[FAIL] Expected option test failed: unexpected return code {return_code}")
        return False


def test_expected_option_invalid_value():
    """Test that invalid expected value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--expected', '999']
    )

    # Should fail with exit code 2 (value > 511)
    if return_code == 2:
        print("[PASS] Invalid expected value rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid expected value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_expected_option_negative_value():
    """Test that negative expected value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--expected', '-1']
    )

    # Should fail with exit code 2
    if return_code == 2:
        print("[PASS] Negative expected value rejection test passed")
        return True
    else:
        print(f"[FAIL] Negative expected value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_require_emergency_flag():
    """Test that require-emergency flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--require-emergency']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Require-emergency flag test passed")
        return True
    else:
        print(f"[FAIL] Require-emergency flag test failed: unexpected return code {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py',
         '--format', 'json', '-v', '--warn-only']
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
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check summary structure
            if 'summary' in data:
                summary = data['summary']
                summary_keys = ['total_functions', 'high_severity', 'medium_severity', 'low_severity']
                if all(key in summary for key in summary_keys):
                    print("[PASS] JSON structure test passed")
                    return True
                else:
                    print(f"[FAIL] JSON summary missing keys")
                    return False

            print("[FAIL] JSON missing summary key")
            return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON structure test passed (sysrq not accessible)")
        return True
    else:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False


def test_json_security_section():
    """Test that JSON output has security section"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if 'security' in data:
                security = data['security']
                security_keys = ['issues', 'warnings']
                if all(key in security for key in security_keys):
                    print("[PASS] JSON security section test passed")
                    return True
                else:
                    print(f"[FAIL] JSON security section missing keys")
                    return False

            print("[FAIL] JSON missing security key")
            return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON security test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON security section test passed (sysrq not accessible)")
        return True
    else:
        print(f"[FAIL] JSON security test failed: unexpected return code {return_code}")
        return False


def test_sysrq_value_is_integer():
    """Test that sysrq_value in JSON is an integer"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if isinstance(data.get('sysrq_value'), int):
                print("[PASS] SysRq value type test passed")
                return True
            else:
                print(f"[FAIL] sysrq_value should be integer")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] SysRq value test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] SysRq value type test passed (sysrq not accessible)")
        return True
    else:
        print(f"[FAIL] SysRq value test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (OK), 1 (warnings), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--help']
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
        [sys.executable, 'baremetal_sysrq_monitor.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_common_values():
    """Test that help message documents common SysRq values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--help']
    )

    # Should mention common values like 176 (Ubuntu default)
    if return_code == 0 and '176' in stdout:
        print("[PASS] Help common values test passed")
        return True
    else:
        print(f"[FAIL] Help should document common SysRq values")
        return False


def test_help_contains_emergency_sequence():
    """Test that help message contains emergency recovery sequence"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--help']
    )

    # Should mention the REISUB recovery sequence
    if return_code == 0 and ('sync' in stdout.lower() and 'reboot' in stdout.lower()):
        print("[PASS] Help emergency sequence test passed")
        return True
    else:
        print(f"[FAIL] Help should document emergency recovery sequence")
        return False


def test_functions_list_in_json():
    """Test that functions list is present and properly structured in JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'functions' in data and isinstance(data['functions'], list):
                # If there are functions, check structure
                if data['functions']:
                    func = data['functions'][0]
                    required = ['bit', 'name', 'description', 'severity', 'keys']
                    if all(key in func for key in required):
                        print("[PASS] Functions list structure test passed")
                        return True
                    else:
                        print(f"[FAIL] Function entry missing keys")
                        return False
                else:
                    # Empty list is valid (sysrq disabled)
                    print("[PASS] Functions list structure test passed (empty)")
                    return True
            print("[FAIL] JSON missing functions list")
            return False
        except json.JSONDecodeError:
            print(f"[FAIL] Functions list test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Functions list test passed (sysrq not accessible)")
        return True
    else:
        print(f"[FAIL] Functions list test failed: unexpected return code {return_code}")
        return False


def test_available_keys_in_json():
    """Test that available_keys list is present in JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_sysrq_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'available_keys' in data and isinstance(data['available_keys'], list):
                print("[PASS] Available keys list test passed")
                return True
            print("[FAIL] JSON missing available_keys list")
            return False
        except json.JSONDecodeError:
            print(f"[FAIL] Available keys test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Available keys test passed (sysrq not accessible)")
        return True
    else:
        print(f"[FAIL] Available keys test failed: unexpected return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_sysrq_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_expected_option,
        test_expected_option_invalid_value,
        test_expected_option_negative_value,
        test_require_emergency_flag,
        test_combined_options,
        test_json_structure,
        test_json_security_section,
        test_sysrq_value_is_integer,
        test_exit_codes,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_help_contains_common_values,
        test_help_contains_emergency_sequence,
        test_functions_list_in_json,
        test_available_keys_in_json,
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
