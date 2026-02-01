#!/usr/bin/env python3
"""
Test script for baremetal_disk_space_forecaster.py functionality.
Tests argument parsing and error handling without requiring specific hardware.
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
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--help']
    )

    if return_code == 0 and 'forecast' in stdout.lower() and 'disk' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_sample_zero():
    """Test that zero sample is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--sample', '0']
    )

    if return_code == 2:
        print("[PASS] Zero sample test passed")
        return True
    else:
        print(f"[FAIL] Zero sample should return exit code 2, got {return_code}")
        return False


def test_invalid_sample_negative():
    """Test that negative sample is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--sample', '-1']
    )

    if return_code != 0:
        print("[PASS] Negative sample test passed")
        return True
    else:
        print(f"[FAIL] Negative sample should fail")
        return False


def test_invalid_sample_too_large():
    """Test that sample > 300 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--sample', '500']
    )

    if return_code == 2:
        print("[PASS] Large sample test passed")
        return True
    else:
        print(f"[FAIL] Sample > 300 should return exit code 2, got {return_code}")
        return False


def test_invalid_warn_days():
    """Test that zero warn-days is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--warn-days', '0']
    )

    if return_code == 2:
        print("[PASS] Zero warn-days test passed")
        return True
    else:
        print(f"[FAIL] Zero warn-days should return exit code 2, got {return_code}")
        return False


def test_invalid_crit_days():
    """Test that zero crit-days is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--crit-days', '0']
    )

    if return_code == 2:
        print("[PASS] Zero crit-days test passed")
        return True
    else:
        print(f"[FAIL] Zero crit-days should return exit code 2, got {return_code}")
        return False


def test_crit_greater_than_warn():
    """Test that crit-days >= warn-days is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py',
         '--crit-days', '30', '--warn-days', '14']
    )

    if return_code == 2:
        print("[PASS] Crit >= warn validation test passed")
        return True
    else:
        print(f"[FAIL] Crit >= warn should return exit code 2, got {return_code}")
        return False


def test_invalid_threshold_low():
    """Test that threshold < 50 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--threshold', '40']
    )

    if return_code == 2:
        print("[PASS] Low threshold test passed")
        return True
    else:
        print(f"[FAIL] Threshold < 50 should return exit code 2, got {return_code}")
        return False


def test_invalid_threshold_high():
    """Test that threshold > 100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--threshold', '110']
    )

    if return_code == 2:
        print("[PASS] High threshold test passed")
        return True
    else:
        print(f"[FAIL] Threshold > 100 should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--format', 'json', '--sample', '1']
    )

    # Should not fail with "invalid choice" error
    if 'invalid choice' not in stderr:
        print("[PASS] Format option test passed")
        return True
    else:
        print("[FAIL] Format option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--format', 'json', '--sample', '1']
    )

    # If no filesystems found, expected to fail with exit code 2
    if return_code == 2:
        if 'filesystem' in stderr.lower() or 'df' in stderr.lower():
            print("[PASS] JSON output format test passed (no filesystems or access issue)")
            return True
        else:
            print(f"[FAIL] Expected filesystem-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'filesystems' in data and 'summary' in data and 'timestamp' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print("[FAIL] JSON output missing expected fields")
                print(f"  Data keys: {list(data.keys())}")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON parsing failed")
            print(f"  Output: {stdout[:100]}")
            return False

    print(f"[FAIL] Unexpected return code: {return_code}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_table_format():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--format', 'table', '--sample', '1']
    )

    # Should either work or fail with no filesystems
    if return_code == 2:
        if 'filesystem' in stderr.lower() or 'df' in stderr.lower():
            print("[PASS] Table format test passed (no filesystems or access issue)")
            return True

    # If succeeds, check for table elements
    if return_code in [0, 1]:
        if 'Mount' in stdout or 'Use%' in stdout or 'Runway' in stdout or '---' in stdout:
            print("[PASS] Table format test passed")
            return True
        else:
            print("[FAIL] Table format missing expected headers")
            print(f"  Output: {stdout[:200]}")
            return False

    print(f"[FAIL] Table format test failed with code {return_code}")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--verbose', '--sample', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--warn-only', '--sample', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_mount_option():
    """Test --mount option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--mount', '/', '--sample', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Mount option test passed")
        return True
    else:
        print("[FAIL] Mount option not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--sample', '1', '--warn-days', '14', '--crit-days', '3',
         '--threshold', '90']
    )

    # Should not fail due to option conflicts
    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:100]}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--sample', '1']
    )

    # Valid exit codes: 0 (no issues), 1 (issues), 2 (no filesystems/access/usage error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_sample_option():
    """Test that --sample option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py', '--sample', '2']
    )

    # Should not fail due to unrecognized option or invalid value
    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Sample option test passed")
        return True
    else:
        print("[FAIL] Sample option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_days_option():
    """Test that --warn-days option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py',
         '--warn-days', '60', '--sample', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Warn-days option test passed")
        return True
    else:
        print("[FAIL] Warn-days option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_crit_days_option():
    """Test that --crit-days option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py',
         '--crit-days', '3', '--sample', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Crit-days option test passed")
        return True
    else:
        print("[FAIL] Crit-days option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_threshold_option():
    """Test that --threshold option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py',
         '--threshold', '90', '--sample', '1']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Threshold option test passed")
        return True
    else:
        print("[FAIL] Threshold option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_nonexistent_mount():
    """Test that nonexistent mount point is handled"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_disk_space_forecaster.py',
         '--mount', '/nonexistent/mount/point', '--sample', '1']
    )

    # Should fail with exit code 2
    if return_code == 2:
        print("[PASS] Nonexistent mount test passed")
        return True
    else:
        print(f"[FAIL] Nonexistent mount should return exit code 2, got {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_disk_space_forecaster.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_sample_zero,
        test_invalid_sample_negative,
        test_invalid_sample_too_large,
        test_invalid_warn_days,
        test_invalid_crit_days,
        test_crit_greater_than_warn,
        test_invalid_threshold_low,
        test_invalid_threshold_high,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_mount_option,
        test_combined_options,
        test_exit_code_validity,
        test_sample_option,
        test_warn_days_option,
        test_crit_days_option,
        test_threshold_option,
        test_nonexistent_mount,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
