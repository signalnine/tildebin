#!/usr/bin/env python3
"""
Test script for baremetal_disk_write_cache_audit.py functionality.
Tests argument parsing and output formatting without requiring root access
or specific disk hardware.
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
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--help']
    )

    if return_code == 0 and 'write cache' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--help']
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
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_format_option_plain():
    """Test that plain format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'plain']
    )

    # Script will run and report on available disks
    # Valid exit codes: 0 (no issues), 1 (warnings), 2 (error/no devices)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected JSON structure
            required_keys = ['summary', 'devices']
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
        # No devices found - acceptable in some environments
        print("[PASS] JSON format option test passed (no devices)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'table']
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
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '-v']
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
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_require_disabled_flag():
    """Test that require-disabled flag is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--require-disabled']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Require-disabled flag test passed")
        return True
    else:
        print(f"[FAIL] Require-disabled flag test failed: unexpected return code {return_code}")
        return False


def test_device_option():
    """Test that device option is accepted"""
    # Use a fake device - should fail gracefully
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '-d', 'nonexistent_device']
    )

    # Should exit with code 2 (device not found)
    if return_code == 2:
        print("[PASS] Device option test passed (correctly rejects invalid device)")
        return True
    else:
        print(f"[FAIL] Device option test failed: expected exit code 2 for invalid device")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py',
         '--format', 'json', '-v', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed: unexpected return code {return_code}")
        return False


def test_json_summary_structure():
    """Test that JSON output has correct summary structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check summary structure
            if 'summary' in data:
                summary = data['summary']
                summary_keys = ['total', 'write_cache_enabled', 'write_cache_disabled',
                               'write_cache_unknown', 'devices_with_issues']
                if all(key in summary for key in summary_keys):
                    print("[PASS] JSON summary structure test passed")
                    return True
                else:
                    missing = [k for k in summary_keys if k not in summary]
                    print(f"[FAIL] JSON summary missing keys: {missing}")
                    return False

            print("[FAIL] JSON missing summary key")
            return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON summary structure test passed (no devices)")
        return True
    else:
        print(f"[FAIL] JSON structure test failed: unexpected return code {return_code}")
        return False


def test_json_devices_is_list():
    """Test that devices in JSON is a list"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if isinstance(data.get('devices'), list):
                print("[PASS] JSON devices type test passed")
                return True
            else:
                print(f"[FAIL] devices should be a list")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON devices test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON devices type test passed (no devices)")
        return True
    else:
        print(f"[FAIL] JSON devices test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (no issues), 1 (warnings), 2 (error/no devices)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_output_contains_report_header():
    """Test that plain output contains report header"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        if 'audit report' in stdout.lower() or 'summary' in stdout.lower():
            print("[PASS] Output header test passed")
            return True
        else:
            print(f"[FAIL] Output should contain report header")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        print("[PASS] Output header test passed (no devices)")
        return True
    else:
        print(f"[FAIL] Output header test failed: unexpected return code {return_code}")
        return False


def test_table_format_has_header():
    """Test that table format has column headers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_write_cache_audit.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Table should have column headers
        if 'device' in stdout.lower() and 'cache' in stdout.lower():
            print("[PASS] Table header test passed")
            return True
        else:
            print(f"[FAIL] Table should have column headers")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        print("[PASS] Table header test passed (no devices)")
        return True
    else:
        print(f"[FAIL] Table header test failed: unexpected return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_disk_write_cache_audit.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_invalid_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_require_disabled_flag,
        test_device_option,
        test_combined_options,
        test_json_summary_structure,
        test_json_devices_is_list,
        test_exit_codes,
        test_output_contains_report_header,
        test_table_format_has_header,
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
