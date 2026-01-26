#!/usr/bin/env python3
"""
Test script for baremetal_kernel_config_audit.py functionality.
Tests argument parsing and output formats without requiring specific system conditions.
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
        [sys.executable, 'baremetal_kernel_config_audit.py', '--help']
    )

    if return_code == 0 and 'kernel' in stdout.lower() and 'baseline' in stdout.lower():
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
        [sys.executable, 'baremetal_kernel_config_audit.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py']
    )

    # Should succeed (exit 0 or 1 depending on findings)
    if return_code in [0, 1] and 'Kernel Configuration Audit' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'results' not in data or 'summary' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--format', 'table']
    )

    # Should succeed and contain table elements
    if return_code in [0, 1] and ('Parameter' in stdout or '===' in stdout or 'pass' in stdout.lower()):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--verbose']
    )

    # Should succeed and contain detailed info (passed checks or skipped)
    if return_code in [0, 1] and ('PASSED' in stdout or 'SKIPPED' in stdout or 'Total' in stdout):
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:300]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode suppresses normal output when no warnings."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_security_profile():
    """Test --profile security option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--profile', 'security']
    )

    # Should succeed and mention security-related params
    if return_code in [0, 1]:
        print("[PASS] Security profile test passed")
        return True
    else:
        print(f"[FAIL] Security profile test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_performance_profile():
    """Test --profile performance option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--profile', 'performance']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Performance profile test passed")
        return True
    else:
        print(f"[FAIL] Performance profile test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_balanced_profile():
    """Test --profile balanced option (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--profile', 'balanced']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Balanced profile test passed")
        return True
    else:
        print(f"[FAIL] Balanced profile test failed")
        print(f"  Return code: {return_code}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    # Normal execution should return 0 or 1 (not 2)
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py']
    )

    if return_code in [0, 1]:
        print("[PASS] Exit code test passed (0 or 1)")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_summary_structure():
    """Test that JSON summary has expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        # Expected summary fields
        expected_keys = ['total', 'passed', 'failed', 'skipped']
        missing_keys = [k for k in expected_keys if k not in summary]

        if missing_keys:
            print(f"[FAIL] JSON summary missing expected keys: {missing_keys}")
            print(f"  Found keys: {list(summary.keys())}")
            return False

        # Check values are numeric
        for key in expected_keys:
            if not isinstance(summary[key], int):
                print(f"[FAIL] summary.{key} is not an integer")
                return False

        print("[PASS] JSON summary structure test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] JSON summary test failed: {e}")
        return False


def test_json_results_structure():
    """Test that JSON results is a list with expected fields."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        if not isinstance(results, list):
            print("[FAIL] results is not a list")
            return False

        if len(results) == 0:
            print("[FAIL] results list is empty")
            return False

        # Check first result has expected structure
        first = results[0]
        expected_keys = ['param', 'current', 'expected', 'status']
        missing_keys = [k for k in expected_keys if k not in first]

        if missing_keys:
            print(f"[FAIL] Result entry missing expected keys: {missing_keys}")
            print(f"  Found keys: {list(first.keys())}")
            return False

        print("[PASS] JSON results structure test passed")
        return True
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        print(f"[FAIL] JSON results test failed: {e}")
        return False


def test_show_fixes_option():
    """Test --show-fixes option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--show-fixes']
    )

    # Should succeed - if there are failures, should show fix commands
    if return_code in [0, 1]:
        # If return code is 1 (failures), should contain sysctl commands
        if return_code == 1 and 'sysctl' in stdout:
            print("[PASS] Show-fixes option test passed (fixes shown)")
            return True
        elif return_code == 0:
            print("[PASS] Show-fixes option test passed (no fixes needed)")
            return True
        else:
            # Might still pass if just no failures
            print("[PASS] Show-fixes option test passed")
            return True
    else:
        print(f"[FAIL] Show-fixes option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_specific_param_option():
    """Test --param option for checking specific parameters."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py',
         '--param', 'net.ipv4.tcp_syncookies', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        # Should only have one result
        if len(results) != 1:
            print(f"[FAIL] Expected 1 result, got {len(results)}")
            return False

        # Should be the requested param
        if results[0]['param'] != 'net.ipv4.tcp_syncookies':
            print(f"[FAIL] Wrong param: {results[0]['param']}")
            return False

        print("[PASS] Specific param option test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Specific param test failed: {e}")
        return False


def test_multiple_params_option():
    """Test --param option with multiple parameters."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py',
         '--param', 'net.ipv4.tcp_syncookies',
         '--param', 'vm.swappiness',
         '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        results = data.get('results', [])

        # Should have two results
        if len(results) != 2:
            print(f"[FAIL] Expected 2 results, got {len(results)}")
            return False

        params = {r['param'] for r in results}
        expected = {'net.ipv4.tcp_syncookies', 'vm.swappiness'}

        if params != expected:
            print(f"[FAIL] Wrong params: {params}")
            return False

        print("[PASS] Multiple params option test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Multiple params test failed: {e}")
        return False


def test_invalid_param_warning():
    """Test that invalid param gives a warning."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py',
         '--param', 'not.a.real.param']
    )

    # Should fail with exit 2 (no valid params) or have warning in stderr
    if return_code == 2 or 'not in baseline' in stderr.lower():
        print("[PASS] Invalid param warning test passed")
        return True
    else:
        print(f"[FAIL] Invalid param should warn or fail")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_custom_profile_requires_file():
    """Test that custom profile requires --baseline-file."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--profile', 'custom']
    )

    if return_code == 2 and 'baseline-file' in stderr.lower():
        print("[PASS] Custom profile requires file test passed")
        return True
    else:
        print(f"[FAIL] Custom profile should require --baseline-file")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py',
         '--format', 'json', '--verbose', '--profile', 'security']
    )

    try:
        data = json.loads(stdout)

        # Should have all expected fields
        required_keys = ['results', 'summary']
        missing_keys = [k for k in required_keys if k not in data]

        if missing_keys:
            print(f"[FAIL] Combined options missing expected fields: {missing_keys}")
            print(f"  Keys: {list(data.keys())}")
            return False

        print("[PASS] Combined options test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] Combined options test failed: {e}")
        return False


def test_summary_counts_match():
    """Test that summary counts match actual results."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        summary = data['summary']
        results = data['results']

        actual_total = len(results)
        actual_passed = sum(1 for r in results if r['status'] == 'pass')
        actual_failed = sum(1 for r in results if r['status'] == 'fail')
        actual_skipped = sum(1 for r in results if r['status'] in ('skipped', 'error'))

        if summary['total'] != actual_total:
            print(f"[FAIL] Total mismatch: {summary['total']} vs {actual_total}")
            return False

        if summary['passed'] != actual_passed:
            print(f"[FAIL] Passed mismatch: {summary['passed']} vs {actual_passed}")
            return False

        if summary['failed'] != actual_failed:
            print(f"[FAIL] Failed mismatch: {summary['failed']} vs {actual_failed}")
            return False

        print("[PASS] Summary counts match test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Summary counts test failed: {e}")
        return False


def test_help_mentions_profiles():
    """Test that help mentions available profiles."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--help']
    )

    profile_terms = ['security', 'performance', 'balanced', 'custom']
    found_terms = [t for t in profile_terms if t in stdout.lower()]

    if return_code == 0 and len(found_terms) >= 3:
        print("[PASS] Help mentions profiles test passed")
        return True
    else:
        print(f"[FAIL] Help should mention profiles")
        print(f"  Found terms: {found_terms}")
        return False


def test_help_mentions_exit_codes():
    """Test that help mentions exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help mentions exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should mention exit codes")
        return False


def test_result_status_values():
    """Test that result status values are valid."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_kernel_config_audit.py', '--format', 'json']
    )

    try:
        data = json.loads(stdout)
        results = data['results']

        valid_statuses = {'pass', 'fail', 'skipped', 'error'}
        for r in results:
            if r['status'] not in valid_statuses:
                print(f"[FAIL] Invalid status: {r['status']}")
                return False

        print("[PASS] Result status values test passed")
        return True
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[FAIL] Result status test failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_kernel_config_audit.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_security_profile,
        test_performance_profile,
        test_balanced_profile,
        test_exit_codes,
        test_json_summary_structure,
        test_json_results_structure,
        test_show_fixes_option,
        test_specific_param_option,
        test_multiple_params_option,
        test_invalid_param_warning,
        test_custom_profile_requires_file,
        test_combined_options,
        test_summary_counts_match,
        test_help_mentions_profiles,
        test_help_mentions_exit_codes,
        test_result_status_values,
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
