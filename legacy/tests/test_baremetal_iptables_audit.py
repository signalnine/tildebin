#!/usr/bin/env python3
"""
Test script for baremetal_iptables_audit.py functionality.
Tests argument parsing and output formats without requiring root access or iptables.
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
        [sys.executable, 'baremetal_iptables_audit.py', '--help']
    )

    if return_code == 0 and 'iptables' in stdout.lower():
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
        [sys.executable, 'baremetal_iptables_audit.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_iptables_audit.py', '--format', 'invalid']
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


def test_table_option_recognized():
    """Test that table option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--table', 'invalid']
    )

    # Should fail with usage error (invalid choice)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Table option recognition test passed")
        return True
    else:
        print(f"[FAIL] Table option recognition test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_max_rules():
    """Test that invalid max-rules value is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--max-rules', '0']
    )

    if return_code == 2 and 'at least 1' in stderr:
        print("[PASS] Invalid max-rules test passed")
        return True
    else:
        print(f"[FAIL] Invalid max-rules test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_invalid_unused_threshold():
    """Test that negative unused-threshold is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--unused-threshold', '-1']
    )

    if return_code == 2 and 'negative' in stderr:
        print("[PASS] Invalid unused-threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid unused-threshold test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_contains_exit_codes():
    """Test that help documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--help']
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
        [sys.executable, 'baremetal_iptables_audit.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout:
        print("[PASS] Help contains examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain examples")
        return False


def test_valid_table_options():
    """Test that valid table options are accepted (argument parsing only)."""
    for table in ['filter', 'nat', 'mangle', 'raw']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_iptables_audit.py', '--table', table, '--help']
        )
        # Just testing argument parsing works (--help makes it exit 0)
        if return_code != 0:
            print(f"[FAIL] Table option '{table}' should be accepted")
            return False

    print("[PASS] Valid table options test passed")
    return True


def test_valid_format_options():
    """Test that valid format options are accepted (argument parsing only)."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_iptables_audit.py', '--format', fmt, '--help']
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
        [sys.executable, 'baremetal_iptables_audit.py', '-v', '--help']
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
        [sys.executable, 'baremetal_iptables_audit.py', '-w', '--help']
    )

    if return_code == 0:
        print("[PASS] Warn-only option accepted test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option should be accepted")
        return False


def test_iptables_missing_handling():
    """Test handling when iptables is not available."""
    # Run the script - it should either work (if iptables present) or exit 2 (if missing)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py']
    )

    # Valid exit codes: 0 (success), 1 (warnings), 2 (iptables missing/permission denied)
    if return_code in [0, 1, 2]:
        print("[PASS] Iptables handling test passed")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_json_format_argument_parsing():
    """Test JSON format argument is properly parsed."""
    # This tests argument parsing - actual output depends on iptables availability
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--format', 'json']
    )

    # If iptables not available, expect exit 2 with error message
    # If available, expect valid JSON output
    if return_code == 2:
        # iptables not available - that's OK for this test
        if 'iptables' in stderr.lower() or 'permission' in stderr.lower():
            print("[PASS] JSON format argument parsing test passed (iptables unavailable)")
            return True
    elif return_code in [0, 1]:
        # iptables available - verify JSON output
        try:
            data = json.loads(stdout)
            if 'stats' in data and 'issues' in data:
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


def test_max_rules_custom_value():
    """Test custom max-rules value is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--max-rules', '100', '--help']
    )

    if return_code == 0:
        print("[PASS] Custom max-rules value test passed")
        return True
    else:
        print(f"[FAIL] Custom max-rules value should be accepted")
        return False


def test_unused_threshold_custom_value():
    """Test custom unused-threshold value is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--unused-threshold', '100', '--help']
    )

    if return_code == 0:
        print("[PASS] Custom unused-threshold value test passed")
        return True
    else:
        print(f"[FAIL] Custom unused-threshold value should be accepted")
        return False


def test_combined_options():
    """Test multiple options combined."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py',
         '--format', 'table',
         '--verbose',
         '--warn-only',
         '--table', 'nat',
         '--max-rules', '25',
         '--help']
    )

    if return_code == 0:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options should be accepted")
        return False


def test_help_describes_issues():
    """Test that help describes common issues detected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_iptables_audit.py', '--help']
    )

    issues_mentioned = [
        'rule count',
        'empty',
        'permissive',
        'unused'
    ]

    stdout_lower = stdout.lower()
    found = sum(1 for issue in issues_mentioned if issue in stdout_lower)

    if return_code == 0 and found >= 3:
        print("[PASS] Help describes issues test passed")
        return True
    else:
        print(f"[FAIL] Help should describe common issues (found {found}/4)")
        return False


if __name__ == "__main__":
    print("Testing baremetal_iptables_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_table_option_recognized,
        test_invalid_max_rules,
        test_invalid_unused_threshold,
        test_help_contains_exit_codes,
        test_help_contains_examples,
        test_valid_table_options,
        test_valid_format_options,
        test_verbose_option_accepted,
        test_warn_only_option_accepted,
        test_iptables_missing_handling,
        test_json_format_argument_parsing,
        test_max_rules_custom_value,
        test_unused_threshold_custom_value,
        test_combined_options,
        test_help_describes_issues,
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
