#!/usr/bin/env python3
"""
Test script for baremetal_selinux_apparmor_monitor.py functionality.
Tests argument parsing and output formats without requiring SELinux/AppArmor.
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
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--help']
    )

    if return_code == 0 and 'selinux' in stdout.lower() and 'apparmor' in stdout.lower():
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
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_recognized():
    """Test that format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (invalid choice)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Format option recognition test passed")
        return True
    else:
        print(f"[FAIL] Format option recognition test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_hours():
    """Test that invalid hours value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--hours', '0']
    )

    if return_code == 2 and 'at least 1' in stderr:
        print("[PASS] Invalid hours test passed")
        return True
    else:
        print(f"[FAIL] Invalid hours test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_limit():
    """Test that invalid limit value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--limit', '0']
    )

    if return_code == 2 and 'at least 1' in stderr:
        print("[PASS] Invalid limit test passed")
        return True
    else:
        print(f"[FAIL] Invalid limit test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_contains_exit_codes():
    """Test that help documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_examples():
    """Test that help contains usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help contains examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain examples")
        return False


def test_valid_format_options():
    """Test that valid format options are accepted (argument parsing only)."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--format', fmt, '--help']
        )
        # Just testing argument parsing works
        if return_code != 0:
            print(f"[FAIL] Format option '{fmt}' should be accepted")
            return False

    print("[PASS] Valid format options test passed")
    return True


def test_verbose_option_accepted():
    """Test that verbose option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '-v', '--help']
    )

    if return_code == 0:
        print("[PASS] Verbose option accepted test passed")
        return True
    else:
        print(f"[FAIL] Verbose option should be accepted")
        return False


def test_warn_only_option_accepted():
    """Test that warn-only option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '-w', '--help']
    )

    if return_code == 0:
        print("[PASS] Warn-only option accepted test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option should be accepted")
        return False


def test_hours_option_accepted():
    """Test that hours option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--hours', '12', '--help']
    )

    if return_code == 0:
        print("[PASS] Hours option accepted test passed")
        return True
    else:
        print(f"[FAIL] Hours option should be accepted")
        return False


def test_limit_option_accepted():
    """Test that limit option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--limit', '50', '--help']
    )

    if return_code == 0:
        print("[PASS] Limit option accepted test passed")
        return True
    else:
        print(f"[FAIL] Limit option should be accepted")
        return False


def test_lsm_missing_handling():
    """Test handling when neither SELinux nor AppArmor is available."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py']
    )

    # Valid exit codes: 0 (success), 1 (warnings), 2 (LSM missing)
    if return_code in [0, 1, 2]:
        print("[PASS] LSM handling test passed")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_json_format_argument_parsing():
    """Test JSON format argument is properly parsed."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--format', 'json']
    )

    # If LSM not available, expect exit 2 with error message
    # If available, expect valid JSON output
    if return_code == 2:
        # LSM not available - that's OK for this test
        if 'selinux' in stderr.lower() or 'apparmor' in stderr.lower():
            print("[PASS] JSON format argument parsing test passed (LSM unavailable)")
            return True
    elif return_code in [0, 1]:
        # LSM available - verify JSON output
        try:
            data = json.loads(stdout)
            if 'selinux' in data or 'apparmor' in data:
                print("[PASS] JSON format argument parsing test passed (valid JSON)")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output: {stdout[:200]}")
            return False

    print(f"[FAIL] Unexpected state: rc={return_code}")
    return False


def test_combined_options():
    """Test multiple options combined."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py',
         '--format', 'table',
         '--verbose',
         '--warn-only',
         '--hours', '12',
         '--limit', '10',
         '--help']
    )

    if return_code == 0:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options should be accepted")
        return False


def test_help_mentions_security_modules():
    """Test that help mentions both security modules."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--help']
    )

    stdout_lower = stdout.lower()
    has_selinux = 'selinux' in stdout_lower
    has_apparmor = 'apparmor' in stdout_lower

    if return_code == 0 and has_selinux and has_apparmor:
        print("[PASS] Help mentions security modules test passed")
        return True
    else:
        print(f"[FAIL] Help should mention SELinux and AppArmor")
        return False


def test_help_mentions_distros():
    """Test that help mentions which distros use which LSM."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--help']
    )

    stdout_lower = stdout.lower()
    has_rhel = 'rhel' in stdout_lower or 'centos' in stdout_lower or 'fedora' in stdout_lower
    has_ubuntu = 'ubuntu' in stdout_lower or 'debian' in stdout_lower

    if return_code == 0 and (has_rhel or has_ubuntu):
        print("[PASS] Help mentions distros test passed")
        return True
    else:
        print(f"[FAIL] Help should mention which distros use which LSM")
        return False


def test_negative_hours_rejected():
    """Test that negative hours value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_selinux_apparmor_monitor.py', '--hours', '-5']
    )

    # argparse should reject negative integers or script should validate
    if return_code != 0:
        print("[PASS] Negative hours rejected test passed")
        return True
    else:
        print(f"[FAIL] Negative hours should be rejected")
        return False


if __name__ == "__main__":
    print("Testing baremetal_selinux_apparmor_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_invalid_hours,
        test_invalid_limit,
        test_help_contains_exit_codes,
        test_help_contains_examples,
        test_valid_format_options,
        test_verbose_option_accepted,
        test_warn_only_option_accepted,
        test_hours_option_accepted,
        test_limit_option_accepted,
        test_lsm_missing_handling,
        test_json_format_argument_parsing,
        test_combined_options,
        test_help_mentions_security_modules,
        test_help_mentions_distros,
        test_negative_hours_rejected,
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
