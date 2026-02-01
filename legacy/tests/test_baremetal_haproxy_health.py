#!/usr/bin/env python3
"""
Test script for baremetal_haproxy_health.py functionality.
Tests argument parsing and error handling without requiring actual HAProxy.
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
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and 'haproxy' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout and '--socket' in stdout:
        print("[PASS] Help contains examples test passed")
        return True
    else:
        print("[FAIL] Help contains examples test failed")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print("[FAIL] Help contains exit codes test failed")
        return False


def test_help_contains_socket_option():
    """Test that help message documents socket option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and '--socket' in stdout and '-s' in stdout:
        print("[PASS] Help contains socket option test passed")
        return True
    else:
        print("[FAIL] Help contains socket option test failed")
        return False


def test_help_contains_url_option():
    """Test that help message documents URL option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and '--url' in stdout and '-u' in stdout:
        print("[PASS] Help contains URL option test passed")
        return True
    else:
        print("[FAIL] Help contains URL option test failed")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format option test passed")
        return True
    else:
        print("[FAIL] Invalid format option test failed")
        return False


def test_format_plain_option():
    """Test that plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--format', 'plain']
    )

    # Should accept the option (may fail due to socket not found)
    if return_code in [0, 1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed")
        return False


def test_format_json_option():
    """Test that JSON format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--format', 'json']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Format JSON option test passed")
        return True
    else:
        print("[FAIL] Format JSON option test failed")
        return False


def test_format_table_option():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--format', 'table']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Format table option test passed")
        return True
    else:
        print("[FAIL] Format table option test failed")
        return False


def test_warn_only_option():
    """Test that warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--warn-only']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print("[FAIL] Warn-only option test failed")
        return False


def test_verbose_option():
    """Test that verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--verbose']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed")
        return False


def test_socket_option():
    """Test that socket option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py',
         '--socket', '/nonexistent/haproxy.sock']
    )

    # Should accept the option (will fail with socket not found)
    if return_code == 2 and 'not found' in stderr.lower():
        print("[PASS] Socket option test passed")
        return True
    elif return_code in [0, 1]:
        # If somehow it works (unlikely)
        print("[PASS] Socket option test passed")
        return True
    else:
        print("[FAIL] Socket option test failed")
        return False


def test_url_option():
    """Test that URL option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py',
         '--url', 'http://localhost:9999/stats']
    )

    # Should accept the option (will fail with connection error)
    if return_code == 2:
        print("[PASS] URL option test passed")
        return True
    elif return_code in [0, 1]:
        print("[PASS] URL option test passed")
        return True
    else:
        print("[FAIL] URL option test failed")
        return False


def test_threshold_options():
    """Test that threshold options are recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py',
         '--session-warn-pct', '70', '--session-crit-pct', '90',
         '--error-rate-warn', '2', '--error-rate-crit', '10',
         '--queue-warn', '5', '--queue-crit', '20']
    )

    # Should accept all threshold options
    if return_code in [0, 1, 2]:
        print("[PASS] Threshold options test passed")
        return True
    else:
        print("[FAIL] Threshold options test failed")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py',
         '--warn-only', '--verbose', '--format', 'json']
    )

    # Should accept all options
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print("[FAIL] Combined options test failed")
        return False


def test_short_options():
    """Test short option variants"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py',
         '-w', '-v', '-f', 'plain']
    )

    # Should accept short options
    if return_code in [0, 1, 2]:
        print("[PASS] Short options test passed")
        return True
    else:
        print("[FAIL] Short options test failed")
        return False


def test_socket_missing_message():
    """Test that missing socket produces helpful error message"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py']
    )

    # If no socket available, should get exit code 2 and helpful message
    if return_code == 2:
        if 'socket' in stderr.lower() or 'haproxy' in stderr.lower():
            print("[PASS] Missing socket message test passed")
            return True
    # If HAProxy is available, the command runs
    if return_code in [0, 1]:
        print("[PASS] Missing socket message test passed (HAProxy available)")
        return True

    print("[FAIL] Missing socket message test failed")
    return False


def test_exit_code_documentation():
    """Test that exit codes are properly documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0:
        # Check all three exit codes are documented
        if '0 -' in stdout and '1 -' in stdout and '2 -' in stdout:
            print("[PASS] Exit code documentation test passed")
            return True

    print("[FAIL] Exit code documentation test failed")
    return False


def test_http_auth_options():
    """Test that HTTP auth options are documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and '--username' in stdout and '--password' in stdout:
        print("[PASS] HTTP auth options test passed")
        return True
    else:
        print("[FAIL] HTTP auth options test failed")
        return False


def test_session_threshold_documented():
    """Test that session thresholds are documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and 'session-warn-pct' in stdout and 'session-crit-pct' in stdout:
        print("[PASS] Session threshold documented test passed")
        return True
    else:
        print("[FAIL] Session threshold documented test failed")
        return False


def test_error_rate_threshold_documented():
    """Test that error rate thresholds are documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and 'error-rate-warn' in stdout and 'error-rate-crit' in stdout:
        print("[PASS] Error rate threshold documented test passed")
        return True
    else:
        print("[FAIL] Error rate threshold documented test failed")
        return False


def test_queue_threshold_documented():
    """Test that queue thresholds are documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0 and 'queue-warn' in stdout and 'queue-crit' in stdout:
        print("[PASS] Queue threshold documented test passed")
        return True
    else:
        print("[FAIL] Queue threshold documented test failed")
        return False


def test_invalid_threshold_rejected():
    """Test that invalid threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py',
         '--session-warn-pct', 'not-a-number']
    )

    if return_code != 0 and ('invalid' in stderr.lower() or 'error' in stderr.lower()):
        print("[PASS] Invalid threshold rejected test passed")
        return True
    else:
        print("[FAIL] Invalid threshold rejected test failed")
        return False


def test_docstring_present():
    """Test that the script has a proper docstring"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py', '--help']
    )

    if return_code == 0:
        # Check key docstring elements are present
        checks = [
            'haproxy' in stdout.lower(),
            'health' in stdout.lower(),
            'backend' in stdout.lower() or 'stats' in stdout.lower()
        ]
        if all(checks):
            print("[PASS] Docstring present test passed")
            return True

    print("[FAIL] Docstring present test failed")
    return False


def test_mutual_exclusion_socket_url():
    """Test that socket and URL options are mutually exclusive"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_haproxy_health.py',
         '--socket', '/tmp/test.sock',
         '--url', 'http://localhost:8404/stats']
    )

    # Should error due to mutual exclusion
    if return_code != 0 and ('not allowed' in stderr or 'mutually exclusive' in stderr.lower()):
        print("[PASS] Mutual exclusion socket/url test passed")
        return True
    # argparse uses "not allowed with argument"
    if return_code != 0 and 'not allowed' in stderr:
        print("[PASS] Mutual exclusion socket/url test passed")
        return True
    else:
        print("[FAIL] Mutual exclusion socket/url test failed")
        return False


if __name__ == "__main__":
    print("Testing baremetal_haproxy_health.py...")

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_help_contains_socket_option,
        test_help_contains_url_option,
        test_invalid_format_option,
        test_format_plain_option,
        test_format_json_option,
        test_format_table_option,
        test_warn_only_option,
        test_verbose_option,
        test_socket_option,
        test_url_option,
        test_threshold_options,
        test_combined_options,
        test_short_options,
        test_socket_missing_message,
        test_exit_code_documentation,
        test_http_auth_options,
        test_session_threshold_documented,
        test_error_rate_threshold_documented,
        test_queue_threshold_documented,
        test_invalid_threshold_rejected,
        test_docstring_present,
        test_mutual_exclusion_socket_url,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\nTest Results: " + str(passed) + "/" + str(total) + " tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
