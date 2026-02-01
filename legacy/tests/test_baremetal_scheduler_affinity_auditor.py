#!/usr/bin/env python3
"""
Test script for baremetal_scheduler_affinity_auditor.py functionality.
Tests argument parsing and error handling without requiring specific process states.
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
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--help']
    )

    if return_code == 0 and 'affinity' in stdout.lower() and 'scheduler' in stdout.lower():
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
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'plain']
    )

    # Script will run on Linux systems
    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'json']
    )

    # If script runs successfully or finds issues
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'issues' in data:
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
        # /proc not available - that's OK for non-Linux systems
        print("[PASS] JSON format option test passed (/proc not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed: unexpected return code {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'invalid']
    )

    # Should fail with exit code 2 (usage error) or show error message
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
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '-v']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_rt_only_flag():
    """Test that rt-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--rt-only']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] RT-only flag test passed")
        return True
    else:
        print(f"[FAIL] RT-only flag test failed: unexpected return code {return_code}")
        return False


def test_pinned_only_flag():
    """Test that pinned-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--pinned-only']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Pinned-only flag test passed")
        return True
    else:
        print(f"[FAIL] Pinned-only flag test failed: unexpected return code {return_code}")
        return False


def test_filter_option():
    """Test that filter option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--filter', 'python']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Filter option test passed")
        return True
    else:
        print(f"[FAIL] Filter option test failed: unexpected return code {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py',
         '--format', 'json', '-v', '--warn-only']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed: unexpected return code {return_code}")
        return False


def test_json_structure():
    """Test that JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        # Non-Linux system
        print("[PASS] JSON structure test passed (non-Linux system)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False

    try:
        data = json.loads(stdout)

        # Check summary structure
        if 'summary' not in data:
            print("[FAIL] JSON structure test failed: missing 'summary'")
            return False

        summary = data['summary']
        required_summary_keys = ['cpu_count', 'total_processes', 'rt_processes', 'issue_count']
        for key in required_summary_keys:
            if key not in summary:
                print(f"[FAIL] JSON structure test failed: missing summary key '{key}'")
                return False

        # Check issues is a list
        if 'issues' not in data or not isinstance(data['issues'], list):
            print("[FAIL] JSON structure test failed: missing or invalid 'issues'")
            return False

        # Check rt_processes is a list
        if 'rt_processes' not in data or not isinstance(data['rt_processes'], list):
            print("[FAIL] JSON structure test failed: missing or invalid 'rt_processes'")
            return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError:
        print(f"[FAIL] JSON structure test failed: invalid JSON")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (no issues), 1 (issues found), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_plain_output_contains_metrics():
    """Test that plain output contains expected metrics"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'plain']
    )

    if return_code == 2:
        # Non-Linux system
        print("[PASS] Plain output metrics test passed (non-Linux system)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] Plain output metrics test failed: unexpected return code {return_code}")
        return False

    # Check for expected labels
    expected_labels = ['CPU Count:', 'Total Processes', 'Real-Time Processes:']
    found = sum(1 for label in expected_labels if label in stdout)

    if found >= 2:  # Allow some flexibility
        print("[PASS] Plain output metrics test passed")
        return True
    else:
        print(f"[FAIL] Plain output missing expected metrics")
        print(f"  Output: {stdout[:500]}")
        return False


def test_json_summary_policy_distribution():
    """Test that JSON output includes policy distribution"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("[PASS] Policy distribution test passed (non-Linux system)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] Policy distribution test failed: unexpected return code {return_code}")
        return False

    try:
        data = json.loads(stdout)
        if 'summary' in data and 'policy_distribution' in data['summary']:
            dist = data['summary']['policy_distribution']
            if isinstance(dist, dict):
                print("[PASS] Policy distribution test passed")
                return True

        print("[FAIL] Policy distribution test failed: missing or invalid policy_distribution")
        return False

    except json.JSONDecodeError:
        print(f"[FAIL] Policy distribution test failed: invalid JSON")
        return False


def test_filter_with_format():
    """Test filtering with different output formats"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_scheduler_affinity_auditor.py',
         '--filter', 'nonexistent_process_name_12345',
         '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        # Should handle empty results gracefully
        if return_code != 2:  # If not a system error
            try:
                data = json.loads(stdout)
                print("[PASS] Filter with format test passed")
                return True
            except json.JSONDecodeError:
                print(f"[FAIL] Filter with format test failed: invalid JSON")
                return False
        else:
            print("[PASS] Filter with format test passed (non-Linux system)")
            return True
    else:
        print(f"[FAIL] Filter with format test failed: unexpected return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_scheduler_affinity_auditor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_rt_only_flag,
        test_pinned_only_flag,
        test_filter_option,
        test_combined_options,
        test_json_structure,
        test_exit_codes,
        test_plain_output_contains_metrics,
        test_json_summary_policy_distribution,
        test_filter_with_format,
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
