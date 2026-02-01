#!/usr/bin/env python3
"""
Test script for baremetal_kernel_hardening_audit.py functionality.
Tests argument parsing and output formats without requiring specific kernel features.
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
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--help']
    )

    if return_code == 0 and 'kernel' in stdout.lower() and 'hardening' in stdout.lower():
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
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'invalid']
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


def test_help_contains_exit_codes():
    """Test that help documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--help']
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
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--help']
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
            [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', fmt, '--help']
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
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '-v', '--help']
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
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '-w', '--help']
    )

    if return_code == 0:
        print("[PASS] Warn-only option accepted test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option should be accepted")
        return False


def test_strict_option_accepted():
    """Test that strict option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--strict', '--help']
    )

    if return_code == 0:
        print("[PASS] Strict option accepted test passed")
        return True
    else:
        print(f"[FAIL] Strict option should be accepted")
        return False


def test_execution():
    """Test that the script runs without crashing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py']
    )

    # Valid exit codes: 0 (success), 1 (warnings)
    if return_code in [0, 1]:
        print("[PASS] Execution test passed")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_format_output():
    """Test JSON format produces valid output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'checks' in data and 'summary' in data:
                print("[PASS] JSON format output test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected keys")
                print(f"  Keys found: {list(data.keys())}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] Invalid JSON output: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_json_contains_aslr():
    """Test JSON output contains ASLR check."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'checks' in data and 'aslr' in data['checks']:
                aslr = data['checks']['aslr']
                if 'status' in aslr and 'level' in aslr:
                    print("[PASS] JSON contains ASLR test passed")
                    return True
                else:
                    print("[FAIL] ASLR data incomplete")
                    return False
            else:
                print("[FAIL] ASLR check not found in output")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_json_contains_spectre_meltdown():
    """Test JSON output contains Spectre/Meltdown check."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'checks' in data and 'spectre_meltdown' in data['checks']:
                print("[PASS] JSON contains Spectre/Meltdown test passed")
                return True
            else:
                print("[FAIL] Spectre/Meltdown check not found")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_table_format_output():
    """Test table format produces output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Table output should have header
        if 'CHECK' in stdout and 'STATUS' in stdout:
            print("[PASS] Table format output test passed")
            return True
        else:
            print("[FAIL] Table format missing expected headers")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_plain_format_output():
    """Test plain format produces output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Plain output should mention ASLR
        if 'ASLR' in stdout:
            print("[PASS] Plain format output test passed")
            return True
        else:
            print("[FAIL] Plain format missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_verbose_output():
    """Test verbose mode produces more output."""
    return_code_normal, stdout_normal, _ = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py']
    )

    return_code_verbose, stdout_verbose, _ = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '-v']
    )

    if return_code_normal in [0, 1] and return_code_verbose in [0, 1]:
        # Verbose output should be longer or equal
        if len(stdout_verbose) >= len(stdout_normal):
            print("[PASS] Verbose output test passed")
            return True
        else:
            print("[FAIL] Verbose output should be >= normal output")
            return False
    else:
        print(f"[FAIL] Unexpected return codes")
        return False


def test_combined_options():
    """Test multiple options combined."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py',
         '--format', 'table',
         '--verbose',
         '--warn-only',
         '--strict',
         '--help']
    )

    if return_code == 0:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options should be accepted")
        return False


def test_help_mentions_aslr():
    """Test that help mentions ASLR."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--help']
    )

    if return_code == 0 and 'aslr' in stdout.lower():
        print("[PASS] Help mentions ASLR test passed")
        return True
    else:
        print(f"[FAIL] Help should mention ASLR")
        return False


def test_help_mentions_spectre():
    """Test that help mentions Spectre/Meltdown."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--help']
    )

    stdout_lower = stdout.lower()
    if return_code == 0 and ('spectre' in stdout_lower or 'meltdown' in stdout_lower):
        print("[PASS] Help mentions Spectre/Meltdown test passed")
        return True
    else:
        print(f"[FAIL] Help should mention Spectre/Meltdown")
        return False


def test_help_mentions_smep_smap():
    """Test that help mentions SMEP/SMAP."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--help']
    )

    stdout_lower = stdout.lower()
    if return_code == 0 and ('smep' in stdout_lower or 'smap' in stdout_lower):
        print("[PASS] Help mentions SMEP/SMAP test passed")
        return True
    else:
        print(f"[FAIL] Help should mention SMEP/SMAP")
        return False


def test_help_mentions_pti():
    """Test that help mentions PTI/KPTI."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--help']
    )

    stdout_lower = stdout.lower()
    if return_code == 0 and ('pti' in stdout_lower or 'kpti' in stdout_lower):
        print("[PASS] Help mentions PTI/KPTI test passed")
        return True
    else:
        print(f"[FAIL] Help should mention PTI/KPTI")
        return False


def test_json_summary_keys():
    """Test JSON summary contains expected keys."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data:
                expected_keys = ['aslr', 'kaslr', 'nx_dep', 'smep_smap', 'pti']
                summary = data['summary']
                missing = [k for k in expected_keys if k not in summary]
                if not missing:
                    print("[PASS] JSON summary keys test passed")
                    return True
                else:
                    print(f"[FAIL] Summary missing keys: {missing}")
                    return False
            else:
                print("[FAIL] No summary in output")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_checks_have_status():
    """Test that all checks have a status field."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'checks' in data:
                for check_name, check_data in data['checks'].items():
                    if 'status' not in check_data:
                        print(f"[FAIL] Check '{check_name}' missing status")
                        return False
                print("[PASS] Checks have status test passed")
                return True
            else:
                print("[FAIL] No checks in output")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_checks_have_details():
    """Test that all checks have a details field."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_hardening_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'checks' in data:
                for check_name, check_data in data['checks'].items():
                    if 'details' not in check_data:
                        print(f"[FAIL] Check '{check_name}' missing details")
                        return False
                print("[PASS] Checks have details test passed")
                return True
            else:
                print("[FAIL] No checks in output")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_kernel_hardening_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_recognized,
        test_help_contains_exit_codes,
        test_help_contains_examples,
        test_valid_format_options,
        test_verbose_option_accepted,
        test_warn_only_option_accepted,
        test_strict_option_accepted,
        test_execution,
        test_json_format_output,
        test_json_contains_aslr,
        test_json_contains_spectre_meltdown,
        test_table_format_output,
        test_plain_format_output,
        test_verbose_output,
        test_combined_options,
        test_help_mentions_aslr,
        test_help_mentions_spectre,
        test_help_mentions_smep_smap,
        test_help_mentions_pti,
        test_json_summary_keys,
        test_checks_have_status,
        test_checks_have_details,
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
