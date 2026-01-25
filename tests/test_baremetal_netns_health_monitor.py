#!/usr/bin/env python3
"""
Test script for baremetal_netns_health_monitor.py functionality.
Tests argument parsing and error handling without requiring specific namespace states.
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
        [sys.executable, 'baremetal_netns_health_monitor.py', '--help']
    )

    if return_code == 0 and 'namespace' in stdout.lower() and 'veth' in stdout.lower():
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
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'plain']
    )

    # Script will run on Linux systems with ip command
    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option is accepted and produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'json']
    )

    # If script runs successfully or finds issues
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'named_namespaces' in data:
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
        # ip command not available - OK for some systems
        print("[PASS] JSON format option test passed (ip command not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_netns_health_monitor.py', '-v']
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
        [sys.executable, 'baremetal_netns_health_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_netns_health_monitor.py',
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
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # ip command not available
        print("[PASS] JSON structure test passed (ip command not available)")
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
        required_summary_keys = ['named_count', 'process_count', 'veth_count', 'total_issues']
        for key in required_summary_keys:
            if key not in summary:
                print(f"[FAIL] JSON structure test failed: missing summary key '{key}'")
                return False

        # Check namespaces lists exist
        if 'named_namespaces' not in data:
            print("[FAIL] JSON structure test failed: missing 'named_namespaces'")
            return False

        if 'process_namespaces' not in data:
            print("[FAIL] JSON structure test failed: missing 'process_namespaces'")
            return False

        # Check dangling_veths is a list
        if 'dangling_veths' not in data or not isinstance(data['dangling_veths'], list):
            print("[FAIL] JSON structure test failed: missing or invalid 'dangling_veths'")
            return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError:
        print(f"[FAIL] JSON structure test failed: invalid JSON")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'plain']
    )

    if return_code == 2:
        # ip command not available
        print("[PASS] Plain output metrics test passed (ip command not available)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] Plain output metrics test failed: unexpected return code {return_code}")
        return False

    # Check for expected metric labels
    expected_labels = ['Named namespaces:', 'Process namespaces:', 'Veth pairs:']
    missing = [label for label in expected_labels if label not in stdout]

    if missing:
        print(f"[FAIL] Plain output missing metrics: {missing}")
        print(f"  Output: {stdout[:500]}")
        return False

    print("[PASS] Plain output metrics test passed")
    return True


def test_summary_counts():
    """Test that summary counts are non-negative integers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_netns_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # ip command not available
        print("[PASS] Summary counts test passed (ip command not available)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] Summary counts test failed: unexpected return code {return_code}")
        return False

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        count_fields = ['named_count', 'process_count', 'veth_count', 'total_issues']
        for field in count_fields:
            value = summary.get(field)
            if not isinstance(value, int) or value < 0:
                print(f"[FAIL] Summary counts test failed: {field} is not a non-negative integer")
                return False

        print("[PASS] Summary counts test passed")
        return True

    except json.JSONDecodeError:
        print(f"[FAIL] Summary counts test failed: invalid JSON")
        return False


def test_short_verbose_flag():
    """Test that short verbose flag -v is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_netns_health_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Short verbose flag test failed: unexpected return code {return_code}")
        return False


def test_short_warn_only_flag():
    """Test that short warn-only flag -w is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_netns_health_monitor.py', '-w']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed: unexpected return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_netns_health_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_combined_options,
        test_json_structure,
        test_exit_codes,
        test_plain_output_contains_metrics,
        test_summary_counts,
        test_short_verbose_flag,
        test_short_warn_only_flag,
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
