#!/usr/bin/env python3
"""
Test script for baremetal_etcd_health_monitor.py functionality.
Tests argument parsing and error handling without requiring actual etcd cluster.
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
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and 'etcd' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print("[FAIL] Help message test failed - return code: " + str(return_code))
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout and '--endpoints' in stdout:
        print("[PASS] Help contains examples test passed")
        return True
    else:
        print("[FAIL] Help contains examples test failed")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print("[FAIL] Help contains exit codes test failed")
        return False


def test_help_contains_tls_options():
    """Test that help message documents TLS options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and '--cacert' in stdout and '--cert' in stdout and '--key' in stdout:
        print("[PASS] Help contains TLS options test passed")
        return True
    else:
        print("[FAIL] Help contains TLS options test failed")
        return False


def test_help_contains_environment_vars():
    """Test that help documents environment variables"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and 'ETCDCTL_ENDPOINTS' in stdout:
        print("[PASS] Help contains environment variables test passed")
        return True
    else:
        print("[FAIL] Help contains environment variables test failed")
        return False


def test_invalid_format_option():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--format', 'plain']
    )

    # Should accept the option (may fail due to etcdctl not available)
    if return_code in [0, 1, 2]:
        print("[PASS] Format plain option test passed")
        return True
    else:
        print("[FAIL] Format plain option test failed")
        return False


def test_format_json_option():
    """Test that JSON format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--format', 'json']
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
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--warn-only']
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
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--verbose']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print("[FAIL] Verbose option test failed")
        return False


def test_endpoints_option():
    """Test that endpoints option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py',
         '--endpoints', 'https://etcd1:2379,https://etcd2:2379']
    )

    # Should accept the option
    if return_code in [0, 1, 2]:
        print("[PASS] Endpoints option test passed")
        return True
    else:
        print("[FAIL] Endpoints option test failed")
        return False


def test_threshold_options():
    """Test that threshold options are recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py',
         '--db-warn-mb', '1024', '--db-crit-mb', '4096',
         '--latency-warn-ms', '50', '--latency-crit-ms', '200']
    )

    # Should accept all threshold options
    if return_code in [0, 1, 2]:
        print("[PASS] Threshold options test passed")
        return True
    else:
        print("[FAIL] Threshold options test failed")
        return False


def test_tls_options():
    """Test that TLS options are recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py',
         '--cacert', '/nonexistent/ca.crt',
         '--cert', '/nonexistent/client.crt',
         '--key', '/nonexistent/client.key']
    )

    # Should accept TLS options (may fail with etcdctl not found or connection error)
    if return_code in [0, 1, 2]:
        print("[PASS] TLS options test passed")
        return True
    else:
        print("[FAIL] TLS options test failed")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py',
         '--warn-only', '--verbose', '--format', 'json',
         '--endpoints', 'http://127.0.0.1:2379']
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
        [sys.executable, 'baremetal_etcd_health_monitor.py',
         '-w', '-v', '-f', 'plain', '-e', 'http://127.0.0.1:2379']
    )

    # Should accept short options
    if return_code in [0, 1, 2]:
        print("[PASS] Short options test passed")
        return True
    else:
        print("[FAIL] Short options test failed")
        return False


def test_etcdctl_missing_message():
    """Test that missing etcdctl produces helpful error message"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py']
    )

    # If etcdctl is not available, should get exit code 2 and helpful message
    if return_code == 2:
        if 'etcdctl' in stderr.lower() or 'etcd' in stderr.lower():
            print("[PASS] Missing etcdctl message test passed")
            return True
    # If etcdctl is available, the command runs (success or failure)
    if return_code in [0, 1]:
        print("[PASS] Missing etcdctl message test passed (etcdctl available)")
        return True

    print("[FAIL] Missing etcdctl message test failed")
    return False


def test_exit_code_documentation():
    """Test that exit codes are properly documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0:
        # Check all three exit codes are documented
        if '0 -' in stdout and '1 -' in stdout and '2 -' in stdout:
            print("[PASS] Exit code documentation test passed")
            return True

    print("[FAIL] Exit code documentation test failed")
    return False


def test_default_endpoint():
    """Test that default endpoint is 127.0.0.1:2379"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and '127.0.0.1:2379' in stdout:
        print("[PASS] Default endpoint test passed")
        return True
    else:
        print("[FAIL] Default endpoint test failed")
        return False


def test_db_size_thresholds_documented():
    """Test that database size thresholds are documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and 'db-warn-mb' in stdout and 'db-crit-mb' in stdout:
        print("[PASS] DB size thresholds documented test passed")
        return True
    else:
        print("[FAIL] DB size thresholds documented test failed")
        return False


def test_latency_thresholds_documented():
    """Test that latency thresholds are documented"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0 and 'latency-warn-ms' in stdout and 'latency-crit-ms' in stdout:
        print("[PASS] Latency thresholds documented test passed")
        return True
    else:
        print("[FAIL] Latency thresholds documented test failed")
        return False


def test_invalid_threshold_rejected():
    """Test that invalid threshold values are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_etcd_health_monitor.py',
         '--db-warn-mb', 'not-a-number']
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
        [sys.executable, 'baremetal_etcd_health_monitor.py', '--help']
    )

    if return_code == 0:
        # Check key docstring elements are present
        checks = [
            'etcd' in stdout.lower(),
            'health' in stdout.lower(),
            'cluster' in stdout.lower()
        ]
        if all(checks):
            print("[PASS] Docstring present test passed")
            return True

    print("[FAIL] Docstring present test failed")
    return False


if __name__ == "__main__":
    print("Testing baremetal_etcd_health_monitor.py...")

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_help_contains_tls_options,
        test_help_contains_environment_vars,
        test_invalid_format_option,
        test_format_plain_option,
        test_format_json_option,
        test_format_table_option,
        test_warn_only_option,
        test_verbose_option,
        test_endpoints_option,
        test_threshold_options,
        test_tls_options,
        test_combined_options,
        test_short_options,
        test_etcdctl_missing_message,
        test_exit_code_documentation,
        test_default_endpoint,
        test_db_size_thresholds_documented,
        test_latency_thresholds_documented,
        test_invalid_threshold_rejected,
        test_docstring_present,
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
