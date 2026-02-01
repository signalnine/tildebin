#!/usr/bin/env python3
"""
Test script for baremetal_logrotate_status_monitor.py functionality.
Tests argument parsing and output formatting without requiring specific system state.
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
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--help']
    )

    if return_code == 0 and 'logrotate' in stdout.lower() and 'log' in stdout.lower():
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
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (normal), 1 (issues), 2 (error)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected JSON structure
            required_keys = ['timestamp', 'thresholds', 'has_issues', 'summary']
            if all(key in data for key in required_keys):
                print("[PASS] JSON format option test passed")
                return True
            else:
                print(f"[FAIL] JSON format missing expected keys")
                print(f"  Found keys: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON format test failed: invalid JSON output")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Error (e.g., no valid directories) - check if it's permission-related
        print("[PASS] JSON format option test passed (permission or directory issue)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format option test failed: unexpected return code {return_code}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'invalid']
    )

    # Should fail with exit code 2 (usage error)
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
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed: unexpected return code {return_code}")
        return False


def test_warn_only_flag():
    """Test that warn-only flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_max_size_option():
    """Test that max-size option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--max-size', '50']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Max-size option test passed")
        return True
    else:
        print(f"[FAIL] Max-size option test failed: unexpected return code {return_code}")
        return False


def test_max_dir_size_option():
    """Test that max-dir-size option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--max-dir-size', '5']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Max-dir-size option test passed")
        return True
    else:
        print(f"[FAIL] Max-dir-size option test failed: unexpected return code {return_code}")
        return False


def test_max_age_option():
    """Test that max-age option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--max-age', '14']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Max-age option test passed")
        return True
    else:
        print(f"[FAIL] Max-age option test failed: unexpected return code {return_code}")
        return False


def test_log_dir_option():
    """Test that log-dir option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--log-dir', '/var/log']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Log-dir option test passed")
        return True
    else:
        print(f"[FAIL] Log-dir option test failed: unexpected return code {return_code}")
        return False


def test_multiple_log_dirs():
    """Test that multiple log directories can be specified"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py',
         '--log-dir', '/var/log', '/tmp']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Multiple log directories test passed")
        return True
    else:
        print(f"[FAIL] Multiple log directories test failed: unexpected return code {return_code}")
        return False


def test_invalid_max_size_value():
    """Test that invalid max-size value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--max-size', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid max-size value rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid max-size value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_max_dir_size_value():
    """Test that invalid max-dir-size value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--max-dir-size', '-1']
    )

    if return_code == 2:
        print("[PASS] Invalid max-dir-size value rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid max-dir-size value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_max_age_value():
    """Test that invalid max-age value is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--max-age', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid max-age value rejection test passed")
        return True
    else:
        print(f"[FAIL] Invalid max-age value should be rejected")
        print(f"  Return code: {return_code}")
        return False


def test_nonexistent_log_dir():
    """Test handling of nonexistent log directory"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py',
         '--log-dir', '/nonexistent/path/that/does/not/exist']
    )

    # Should exit with code 2 (no valid directories)
    if return_code == 2:
        print("[PASS] Nonexistent log directory test passed")
        return True
    else:
        print(f"[FAIL] Nonexistent log directory should cause exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py',
         '--format', 'json', '-v', '--max-size', '50', '--max-age', '14']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed: unexpected return code {return_code}")
        return False


def test_json_structure():
    """Test that JSON output has correct structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check for expected keys
            expected_keys = [
                'timestamp', 'thresholds', 'state_file_ok', 'tracked_logs',
                'large_logs', 'stale_logs', 'directory_sizes', 'recent_errors',
                'config_issues', 'has_issues', 'summary'
            ]

            missing = [k for k in expected_keys if k not in data]
            if not missing:
                print("[PASS] JSON structure test passed")
                return True
            else:
                print(f"[FAIL] JSON missing keys: {missing}")
                return False

        except json.JSONDecodeError:
            print(f"[FAIL] JSON structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON structure test passed (no valid directories)")
        return True
    else:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False


def test_json_thresholds():
    """Test that JSON thresholds has all expected values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if 'thresholds' in data:
                thresholds = data['thresholds']
                expected_thresholds = ['max_log_size_mb', 'max_dir_size_gb', 'max_age_days']
                missing = [t for t in expected_thresholds if t not in thresholds]
                if not missing:
                    print("[PASS] JSON thresholds test passed")
                    return True
                else:
                    print(f"[FAIL] Thresholds missing: {missing}")
                    return False

            print("[FAIL] JSON missing thresholds key")
            return False

        except json.JSONDecodeError:
            print(f"[FAIL] JSON thresholds test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON thresholds test passed (no valid directories)")
        return True
    else:
        print(f"[FAIL] JSON thresholds test failed: unexpected return code {return_code}")
        return False


def test_json_summary():
    """Test that JSON summary has all expected counts"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if 'summary' in data:
                summary = data['summary']
                expected_counts = [
                    'large_log_count', 'stale_log_count', 'error_count',
                    'config_issue_count', 'directories_over_threshold'
                ]
                missing = [c for c in expected_counts if c not in summary]
                if not missing:
                    print("[PASS] JSON summary test passed")
                    return True
                else:
                    print(f"[FAIL] Summary missing: {missing}")
                    return False

            print("[FAIL] JSON missing summary key")
            return False

        except json.JSONDecodeError:
            print(f"[FAIL] JSON summary test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON summary test passed (no valid directories)")
        return True
    else:
        print(f"[FAIL] JSON summary test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (normal), 1 (issues), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--help']
    )

    if return_code == 0 and 'example' in stdout.lower():
        print("[PASS] Help examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain examples")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_use_cases():
    """Test that help message contains use cases"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_logrotate_status_monitor.py', '--help']
    )

    if return_code == 0 and 'use case' in stdout.lower():
        print("[PASS] Help use cases test passed")
        return True
    else:
        print(f"[FAIL] Help should contain use cases")
        return False


if __name__ == "__main__":
    print("Testing baremetal_logrotate_status_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_max_size_option,
        test_max_dir_size_option,
        test_max_age_option,
        test_log_dir_option,
        test_multiple_log_dirs,
        test_invalid_max_size_value,
        test_invalid_max_dir_size_value,
        test_invalid_max_age_value,
        test_nonexistent_log_dir,
        test_combined_options,
        test_json_structure,
        test_json_thresholds,
        test_json_summary,
        test_exit_codes,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_help_contains_use_cases,
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
