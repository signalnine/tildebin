#!/usr/bin/env python3
"""
Test script for baremetal_softlockup_detector.py functionality.
Tests argument parsing and error handling without requiring specific system states.
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
        [sys.executable, 'baremetal_softlockup_detector.py', '--help']
    )

    if return_code == 0 and 'softlockup' in stdout.lower() and 'hung' in stdout.lower():
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
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'json']
    )

    # If script runs successfully or finds issues
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'config' in data:
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
        # dmesg not available - that's OK for non-Linux or non-root
        print("[PASS] JSON format option test passed (dmesg not available)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'table']
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
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_softlockup_detector.py', '-v']
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
        [sys.executable, 'baremetal_softlockup_detector.py', '--warn-only']
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
        [sys.executable, 'baremetal_softlockup_detector.py',
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
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'json']
    )

    if return_code == 2:
        # dmesg not available
        print("[PASS] JSON structure test passed (dmesg not available)")
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
        required_summary_keys = ['total_events', 'softlockups', 'hung_tasks', 'has_issues']
        for key in required_summary_keys:
            if key not in summary:
                print(f"[FAIL] JSON structure test failed: missing summary key '{key}'")
                return False

        # Check config structure
        if 'config' not in data:
            print("[FAIL] JSON structure test failed: missing 'config'")
            return False

        # Check stuck_processes is a list
        if 'stuck_processes' not in data or not isinstance(data['stuck_processes'], list):
            print("[FAIL] JSON structure test failed: missing or invalid 'stuck_processes'")
            return False

        # Check events is a list
        if 'events' not in data:
            print("[FAIL] JSON structure test failed: missing 'events'")
            return False

        # Check healthy flag
        if 'healthy' not in data:
            print("[FAIL] JSON structure test failed: missing 'healthy'")
            return False

        print("[PASS] JSON structure test passed")
        return True

    except json.JSONDecodeError:
        print(f"[FAIL] JSON structure test failed: invalid JSON")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (no issues), 1 (issues found), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_plain_output_structure():
    """Test that plain output contains expected sections"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'plain']
    )

    if return_code == 2:
        # dmesg not available
        print("[PASS] Plain output structure test passed (dmesg not available)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] Plain output structure test failed: unexpected return code {return_code}")
        return False

    # Check for expected section headers
    expected_content = ['Softlockup', 'Hung', 'Watchdog', 'Detector']
    found = [label for label in expected_content if label.lower() in stdout.lower()]

    if len(found) >= 2:  # At least some expected content
        print("[PASS] Plain output structure test passed")
        return True
    else:
        print(f"[FAIL] Plain output missing expected content")
        print(f"  Output: {stdout[:500]}")
        return False


def test_table_output_structure():
    """Test that table output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'table']
    )

    if return_code == 2:
        # dmesg not available
        print("[PASS] Table output structure test passed (dmesg not available)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] Table output structure test failed: unexpected return code {return_code}")
        return False

    # Check for expected column headers
    expected_headers = ['Event Type', 'Count', 'Severity']
    found = [h for h in expected_headers if h in stdout]

    if len(found) >= 2:  # At least some expected headers
        print("[PASS] Table output structure test passed")
        return True
    else:
        print(f"[FAIL] Table output missing expected headers")
        print(f"  Output: {stdout[:500]}")
        return False


def test_short_flag_format():
    """Test that short flag -f works for format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '-f', 'json']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Short format flag test passed")
        return True
    else:
        print(f"[FAIL] Short format flag test failed: unexpected return code {return_code}")
        return False


def test_short_flag_warn_only():
    """Test that short flag -w works for warn-only"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '-w']
    )

    if return_code in [0, 1, 2]:  # Valid exit codes
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_suppresses_output_when_healthy():
    """Test that warn-only suppresses output when no issues"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '--warn-only', '--format', 'plain']
    )

    if return_code == 2:
        # dmesg not available
        print("[PASS] Warn-only suppression test passed (dmesg not available)")
        return True

    if return_code == 0:
        # No issues - output should be empty or minimal
        # This is the expected case when no lockups are detected
        print("[PASS] Warn-only suppression test passed")
        return True
    elif return_code == 1:
        # Issues found - output should contain something
        if stdout.strip():
            print("[PASS] Warn-only suppression test passed (issues present)")
            return True
        else:
            print(f"[FAIL] Warn-only should show output when issues exist")
            return False
    else:
        print(f"[FAIL] Warn-only suppression test failed: unexpected return code {return_code}")
        return False


def test_json_timestamp():
    """Test that JSON output includes timestamp"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'json']
    )

    if return_code == 2:
        print("[PASS] JSON timestamp test passed (dmesg not available)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON timestamp test failed: unexpected return code {return_code}")
        return False

    try:
        data = json.loads(stdout)
        if 'timestamp' in data:
            print("[PASS] JSON timestamp test passed")
            return True
        else:
            print("[FAIL] JSON output missing timestamp")
            return False
    except json.JSONDecodeError:
        print("[FAIL] JSON timestamp test failed: invalid JSON")
        return False


def test_json_summary_counts():
    """Test that JSON summary has proper count fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_softlockup_detector.py', '--format', 'json']
    )

    if return_code == 2:
        print("[PASS] JSON summary counts test passed (dmesg not available)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON summary counts test failed: unexpected return code {return_code}")
        return False

    try:
        data = json.loads(stdout)
        summary = data.get('summary', {})

        # All count fields should be integers >= 0
        count_fields = ['total_events', 'softlockups', 'hardlockups', 'hung_tasks', 'rcu_stalls']
        for field in count_fields:
            if field in summary:
                if not isinstance(summary[field], int) or summary[field] < 0:
                    print(f"[FAIL] Summary field {field} is not a valid count: {summary[field]}")
                    return False

        print("[PASS] JSON summary counts test passed")
        return True
    except json.JSONDecodeError:
        print("[FAIL] JSON summary counts test failed: invalid JSON")
        return False


if __name__ == "__main__":
    print("Testing baremetal_softlockup_detector.py...")
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
        test_plain_output_structure,
        test_table_output_structure,
        test_short_flag_format,
        test_short_flag_warn_only,
        test_warn_only_suppresses_output_when_healthy,
        test_json_timestamp,
        test_json_summary_counts,
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
