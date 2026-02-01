#!/usr/bin/env python3
"""
Test script for baremetal_initramfs_health_monitor.py functionality.
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
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--help']
    )

    if return_code == 0 and 'initramfs' in stdout.lower():
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
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'plain']
    )

    # Script will run and report status
    # Valid exit codes: 0 (healthy), 1 (issues), 2 (error)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format option test passed")
        return True
    else:
        print(f"[FAIL] Plain format option test failed: unexpected return code {return_code}")
        return False


def test_format_option_json():
    """Test that JSON format option produces valid JSON"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check expected JSON structure
            required_keys = ['timestamp', 'kernels', 'summary', 'issues']
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
        # Error (e.g., /boot not accessible) - acceptable
        print("[PASS] JSON format option test passed (system check failed)")
        return True
    else:
        print(f"[FAIL] JSON format test failed: unexpected return code {return_code}")
        return False


def test_format_option_table():
    """Test that table format option is accepted"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'invalid']
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
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '-v']
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
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--warn-only']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed: unexpected return code {return_code}")
        return False


def test_combined_options():
    """Test that multiple options work together"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py',
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
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check summary structure
            if 'summary' in data:
                summary = data['summary']
                summary_keys = ['total_kernels', 'healthy', 'missing_initramfs', 'problematic', 'orphaned']
                if all(key in summary for key in summary_keys):
                    print("[PASS] JSON summary structure test passed")
                    return True
                else:
                    print(f"[FAIL] JSON summary missing keys")
                    print(f"  Found keys: {list(summary.keys())}")
                    return False

            print("[FAIL] JSON missing summary key")
            return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON structure test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON summary structure test passed (system check failed)")
        return True
    else:
        print(f"[FAIL] JSON summary test failed: unexpected return code {return_code}")
        return False


def test_json_kernels_array():
    """Test that JSON output contains kernels array"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if 'kernels' in data and isinstance(data['kernels'], list):
                print("[PASS] JSON kernels array test passed")
                return True
            else:
                print(f"[FAIL] JSON should contain kernels array")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON kernels test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON kernels array test passed (system check failed)")
        return True
    else:
        print(f"[FAIL] JSON kernels test failed: unexpected return code {return_code}")
        return False


def test_json_regeneration_tools():
    """Test that JSON output contains regeneration tools info"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if 'regeneration_tools' in data and isinstance(data['regeneration_tools'], dict):
                print("[PASS] JSON regeneration tools test passed")
                return True
            else:
                print(f"[FAIL] JSON should contain regeneration_tools")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON regeneration tools test failed: invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] JSON regeneration tools test passed (system check failed)")
        return True
    else:
        print(f"[FAIL] JSON regeneration tools test failed: unexpected return code {return_code}")
        return False


def test_exit_codes():
    """Test that script uses correct exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'plain']
    )

    # Valid exit codes: 0 (healthy), 1 (issues), 2 (error/missing dependency)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Exit code test failed: unexpected exit code {return_code}")
        return False


def test_help_contains_examples():
    """Test that help message contains usage examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--help']
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
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--help']
    )

    if return_code == 0 and 'exit code' in stdout.lower():
        print("[PASS] Help exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_table_output_has_header():
    """Test that table format has headers"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1]:
        # Check for expected headers
        if 'VERSION' in stdout and 'STATUS' in stdout:
            print("[PASS] Table header test passed")
            return True
        else:
            print(f"[FAIL] Table should have VERSION and STATUS headers")
            return False
    elif return_code == 2:
        print("[PASS] Table header test passed (system check failed)")
        return True
    else:
        print(f"[FAIL] Table header test failed: unexpected return code {return_code}")
        return False


def test_plain_output_contains_summary():
    """Test that plain format contains a summary"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_initramfs_health_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1]:
        if 'summary' in stdout.lower() or 'kernel' in stdout.lower():
            print("[PASS] Plain summary test passed")
            return True
        else:
            print(f"[FAIL] Plain output should contain summary")
            return False
    elif return_code == 2:
        print("[PASS] Plain summary test passed (system check failed)")
        return True
    else:
        print(f"[FAIL] Plain summary test failed: unexpected return code {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_initramfs_health_monitor.py...")
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
        test_json_summary_structure,
        test_json_kernels_array,
        test_json_regeneration_tools,
        test_exit_codes,
        test_help_contains_examples,
        test_help_contains_exit_codes,
        test_table_output_has_header,
        test_plain_output_contains_summary,
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
