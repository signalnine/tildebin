#!/usr/bin/env python3
"""
Test script for baremetal_suid_sgid_audit.py functionality.
Tests argument parsing and output formats without requiring root access.
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--help']
    )

    if return_code == 0 and 'suid' in stdout.lower() and 'sgid' in stdout.lower():
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--help']
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--help']
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
            [sys.executable, 'baremetal_suid_sgid_audit.py', '--format', fmt, '--help']
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-v', '--help']
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-w', '--help']
    )

    if return_code == 0:
        print("[PASS] Warn-only option accepted test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option should be accepted")
        return False


def test_path_option_accepted():
    """Test that path option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr', '--help']
    )

    if return_code == 0:
        print("[PASS] Path option accepted test passed")
        return True
    else:
        print(f"[FAIL] Path option should be accepted")
        return False


def test_exclude_option_accepted():
    """Test that exclude option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-e', '/proc', '--help']
    )

    if return_code == 0:
        print("[PASS] Exclude option accepted test passed")
        return True
    else:
        print(f"[FAIL] Exclude option should be accepted")
        return False


def test_no_expected_check_option():
    """Test that no-expected-check option is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--no-expected-check', '--help']
    )

    if return_code == 0:
        print("[PASS] No-expected-check option accepted test passed")
        return True
    else:
        print(f"[FAIL] No-expected-check option should be accepted")
        return False


def test_execution_limited_path():
    """Test that the script runs when searching a limited path."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr/bin']
    )

    # Valid exit codes: 0 (no issues), 1 (warnings found)
    if return_code in [0, 1]:
        print("[PASS] Execution with limited path test passed")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_format_output():
    """Test JSON format produces valid output."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr/bin', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data:
                print("[PASS] JSON format output test passed")
                return True
            else:
                print("[FAIL] JSON output missing 'summary' key")
                print(f"  Keys found: {list(data.keys())}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] Invalid JSON output: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_json_contains_summary_keys():
    """Test JSON output contains expected summary keys."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr/bin', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data:
                expected_keys = ['total_suid', 'total_sgid', 'unexpected_suid', 'unexpected_sgid']
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


def test_json_contains_file_lists():
    """Test JSON output contains file list keys."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr/bin', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            expected_keys = ['suid_files', 'sgid_files', 'unexpected_suid', 'unexpected_sgid']
            missing = [k for k in expected_keys if k not in data]
            if not missing:
                print("[PASS] JSON file lists test passed")
                return True
            else:
                print(f"[FAIL] Missing keys: {missing}")
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr/bin', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Table output should have header markers
        if 'SUID' in stdout and 'AUDIT' in stdout:
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
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr/bin', '--format', 'plain']
    )

    if return_code in [0, 1]:
        # Plain output should mention SUID
        if 'SUID' in stdout or 'suid' in stdout.lower():
            print("[PASS] Plain format output test passed")
            return True
        else:
            print("[FAIL] Plain format missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_nonexistent_path():
    """Test that nonexistent path is handled."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/nonexistent/path/12345']
    )

    # Should exit with code 2 (usage error)
    if return_code == 2:
        print("[PASS] Nonexistent path test passed")
        return True
    else:
        print(f"[FAIL] Nonexistent path should exit with code 2, got {return_code}")
        return False


def test_help_mentions_suid():
    """Test that help mentions SUID."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--help']
    )

    if return_code == 0 and 'SUID' in stdout:
        print("[PASS] Help mentions SUID test passed")
        return True
    else:
        print(f"[FAIL] Help should mention SUID")
        return False


def test_help_mentions_security():
    """Test that help mentions security."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '--help']
    )

    if return_code == 0 and 'security' in stdout.lower():
        print("[PASS] Help mentions security test passed")
        return True
    else:
        print(f"[FAIL] Help should mention security")
        return False


def test_combined_options():
    """Test multiple options combined."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py',
         '--format', 'table',
         '--verbose',
         '--warn-only',
         '--no-expected-check',
         '--help']
    )

    if return_code == 0:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options should be accepted")
        return False


def test_multiple_paths():
    """Test multiple path arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py',
         '-p', '/usr/bin', '-p', '/usr/sbin', '--help']
    )

    if return_code == 0:
        print("[PASS] Multiple paths test passed")
        return True
    else:
        print(f"[FAIL] Multiple paths should be accepted")
        return False


def test_multiple_excludes():
    """Test multiple exclude arguments."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py',
         '-e', '/proc', '-e', '/sys', '--help']
    )

    if return_code == 0:
        print("[PASS] Multiple excludes test passed")
        return True
    else:
        print(f"[FAIL] Multiple excludes should be accepted")
        return False


def test_short_help_flag():
    """Test short help flag works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-h']
    )

    if return_code == 0 and 'suid' in stdout.lower():
        print("[PASS] Short help flag test passed")
        return True
    else:
        print(f"[FAIL] Short help flag should work")
        return False


def test_docstring_exists():
    """Test that the script has a proper docstring."""
    return_code, stdout, stderr = run_command(
        [sys.executable, '-c',
         'import baremetal_suid_sgid_audit; print(baremetal_suid_sgid_audit.__doc__)']
    )

    if return_code == 0 and 'SUID' in stdout and 'SGID' in stdout:
        print("[PASS] Docstring exists test passed")
        return True
    else:
        print(f"[FAIL] Script should have proper docstring")
        return False


def test_json_file_info_structure():
    """Test that JSON file info has expected structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_suid_sgid_audit.py', '-p', '/usr/bin', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check if any SUID files have the expected structure
            all_files = (data.get('suid_files', []) +
                        data.get('sgid_files', []) +
                        data.get('suid_sgid_files', []))

            if all_files:
                # Check first file has expected keys
                first_file = all_files[0]
                expected_keys = ['path', 'mode', 'owner', 'group', 'is_suid', 'is_sgid']
                missing = [k for k in expected_keys if k not in first_file]
                if not missing:
                    print("[PASS] JSON file info structure test passed")
                    return True
                else:
                    print(f"[FAIL] File info missing keys: {missing}")
                    return False
            else:
                # No files found is OK
                print("[PASS] JSON file info structure test passed (no files)")
                return True

        except json.JSONDecodeError:
            print(f"[FAIL] Invalid JSON output")
            return False
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_suid_sgid_audit.py...")
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
        test_path_option_accepted,
        test_exclude_option_accepted,
        test_no_expected_check_option,
        test_execution_limited_path,
        test_json_format_output,
        test_json_contains_summary_keys,
        test_json_contains_file_lists,
        test_table_format_output,
        test_plain_format_output,
        test_nonexistent_path,
        test_help_mentions_suid,
        test_help_mentions_security,
        test_combined_options,
        test_multiple_paths,
        test_multiple_excludes,
        test_short_help_flag,
        test_docstring_exists,
        test_json_file_info_structure,
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
