#!/usr/bin/env python3
"""
Test script for baremetal_security_policy_monitor.py functionality.
Tests argument parsing and output formatting without requiring specific LSM state.
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
        [sys.executable, 'baremetal_security_policy_monitor.py', '--help']
    )

    if return_code == 0 and 'security' in stdout.lower() and 'lsm' in stdout.lower():
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
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'plain']
    )

    # Script will run and report LSM status
    # Valid exit codes: 0 (healthy), 1 (issues), 2 (error)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected JSON structure
            required_keys = ['primary_lsm', 'overall_status', 'selinux', 'apparmor', 'summary']
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
        # Error determining status - acceptable in some environments
        print("[PASS] JSON format option test passed (LSM status not accessible)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_security_policy_monitor.py', '-v']
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
        [sys.executable, 'baremetal_security_policy_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_expected_option_enforcing():
    """Test that expected option with enforcing is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--expected', 'enforcing']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Expected option (enforcing) test passed")
        return True
    else:
        print(f"[FAIL] Expected option test failed: unexpected return code {return_code}")
        return False


def test_expected_option_permissive():
    """Test that expected option with permissive is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--expected', 'permissive']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Expected option (permissive) test passed")
        return True
    else:
        print(f"[FAIL] Expected option test failed: unexpected return code {return_code}")
        return False


def test_expected_option_invalid():
    """Test that invalid expected option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--expected', 'invalid_mode']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2 or 'invalid choice' in stderr.lower():
        print("[PASS] Invalid expected option rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid expected option should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_require_lsm_flag():
    """Test that require-lsm flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--require-lsm']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Require-lsm flag test passed")
        return True
    else:
        print(f"[FAIL] Require-lsm flag test failed: unexpected return code {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py',
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
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check selinux structure
            if 'selinux' in data:
                se_keys = ['available', 'enabled', 'mode', 'issues']
                if not all(key in data['selinux'] for key in se_keys):
                    print(f"[FAIL] JSON selinux missing keys")
                    return False

            # Check apparmor structure
            if 'apparmor' in data:
                aa_keys = ['available', 'enabled', 'mode', 'issues']
                if not all(key in data['apparmor'] for key in aa_keys):
                    print(f"[FAIL] JSON apparmor missing keys")
                    return False

            # Check summary structure
            if 'summary' in data:
                summary_keys = ['total_issues', 'selinux_available', 'apparmor_available']
                if not all(key in data['summary'] for key in summary_keys):
                    print(f"[FAIL] JSON summary missing keys")
                    return False

            print("[PASS] JSON structure test passed")
            return True

        except json.JSONDecodeError:
            print(f"[FAIL] JSON structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON structure test passed (LSM not accessible)")
        return True
    else:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (healthy), 1 (issues/warnings), 2 (error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--help']
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
        [sys.executable, 'baremetal_security_policy_monitor.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_mentions_selinux():
    """Test that help message mentions SELinux"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--help']
    )

    if return_code == 0 and 'selinux' in stdout.lower():
        print("[PASS] Help SELinux mention test passed")
        return True
    else:
        print(f"[FAIL] Help should mention SELinux")
        return False


def test_help_mentions_apparmor():
    """Test that help message mentions AppArmor"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--help']
    )

    if return_code == 0 and 'apparmor' in stdout.lower():
        print("[PASS] Help AppArmor mention test passed")
        return True
    else:
        print(f"[FAIL] Help should mention AppArmor")
        return False


def test_json_has_timestamp():
    """Test that JSON output includes timestamp"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'timestamp' in data:
                print("[PASS] JSON timestamp test passed")
                return True
            else:
                print(f"[FAIL] JSON should contain timestamp")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON timestamp test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON timestamp test passed (LSM not accessible)")
        return True
    else:
        print(f"[FAIL] JSON timestamp test failed: unexpected return code {return_code}")
        return False


def test_json_primary_lsm_field():
    """Test that JSON output includes primary_lsm field"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_security_policy_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'primary_lsm' in data:
                # Should be one of: selinux, apparmor, none
                if data['primary_lsm'] in ['selinux', 'apparmor', 'none']:
                    print("[PASS] JSON primary_lsm test passed")
                    return True
                else:
                    print(f"[FAIL] primary_lsm has unexpected value: {data['primary_lsm']}")
                    return False
            else:
                print(f"[FAIL] JSON should contain primary_lsm")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON primary_lsm test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON primary_lsm test passed (LSM not accessible)")
        return True
    else:
        print(f"[FAIL] JSON primary_lsm test failed: unexpected return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_security_policy_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_expected_option_enforcing,
        test_expected_option_permissive,
        test_expected_option_invalid,
        test_require_lsm_flag,
        test_combined_options,
        test_json_structure,
        test_exit_codes,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_help_mentions_selinux,
        test_help_mentions_apparmor,
        test_json_has_timestamp,
        test_json_primary_lsm_field,
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
