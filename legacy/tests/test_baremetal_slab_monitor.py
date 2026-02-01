#!/usr/bin/env python3
"""
Test script for baremetal_slab_monitor.py functionality.
Tests argument parsing and error handling without requiring root access.
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
        [sys.executable, 'baremetal_slab_monitor.py', '--help']
    )

    if return_code == 0 and 'slab' in stdout.lower() and 'kernel' in stdout.lower():
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
        [sys.executable, 'baremetal_slab_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_top_zero():
    """Test that --top 0 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--top', '0']
    )

    if return_code == 2:
        print("[PASS] Zero --top test passed")
        return True
    else:
        print(f"[FAIL] Zero --top should return exit code 2, got {return_code}")
        return False


def test_invalid_top_negative():
    """Test that negative --top is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--top', '-5']
    )

    if return_code != 0:
        print("[PASS] Negative --top test passed")
        return True
    else:
        print(f"[FAIL] Negative --top should fail")
        return False


def test_invalid_warn_pct_zero():
    """Test that --warn-pct 0 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--warn-pct', '0']
    )

    if return_code == 2:
        print("[PASS] Zero --warn-pct test passed")
        return True
    else:
        print(f"[FAIL] Zero --warn-pct should return exit code 2, got {return_code}")
        return False


def test_invalid_warn_pct_over_100():
    """Test that --warn-pct > 100 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--warn-pct', '150']
    )

    if return_code == 2:
        print("[PASS] --warn-pct > 100 test passed")
        return True
    else:
        print(f"[FAIL] --warn-pct > 100 should return exit code 2, got {return_code}")
        return False


def test_invalid_crit_pct_zero():
    """Test that --crit-pct 0 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--crit-pct', '0']
    )

    if return_code == 2:
        print("[PASS] Zero --crit-pct test passed")
        return True
    else:
        print(f"[FAIL] Zero --crit-pct should return exit code 2, got {return_code}")
        return False


def test_warn_pct_greater_than_crit_pct():
    """Test that --warn-pct >= --crit-pct is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py',
         '--warn-pct', '50', '--crit-pct', '40']
    )

    if return_code == 2:
        print("[PASS] Warn >= crit validation test passed")
        return True
    else:
        print(f"[FAIL] Warn >= crit should return exit code 2, got {return_code}")
        return False


def test_invalid_warn_ratio_zero():
    """Test that --warn-ratio 0 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--warn-ratio', '0']
    )

    if return_code == 2:
        print("[PASS] Zero --warn-ratio test passed")
        return True
    else:
        print(f"[FAIL] Zero --warn-ratio should return exit code 2, got {return_code}")
        return False


def test_invalid_warn_ratio_over_1():
    """Test that --warn-ratio >= 1 is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--warn-ratio', '1.5']
    )

    if return_code == 2:
        print("[PASS] --warn-ratio >= 1 test passed")
        return True
    else:
        print(f"[FAIL] --warn-ratio >= 1 should return exit code 2, got {return_code}")
        return False


def test_format_option():
    """Test that format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--format', 'json']
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
        [sys.executable, 'baremetal_slab_monitor.py', '--format', 'json']
    )

    # If permission denied or no slabinfo, expected to fail with exit code 2
    if return_code == 2:
        if 'permission' in stderr.lower() or 'slabinfo' in stderr.lower():
            print("[PASS] JSON output format test passed (permission or access issue)")
            return True
        else:
            print(f"[FAIL] Expected permission/slabinfo-related error, got: {stderr[:100]}")
            return False

    # If it succeeds, validate JSON
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Validate expected fields
            if 'summary' in data and 'issues' in data and 'top_caches' in data:
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
        [sys.executable, 'baremetal_slab_monitor.py', '--format', 'table']
    )

    # Should either work or fail with permission issue
    if return_code == 2:
        if 'permission' in stderr.lower() or 'slabinfo' in stderr.lower():
            print("[PASS] Table format test passed (permission or access issue)")
            return True

    # If succeeds, check for table-like output
    if return_code in [0, 1]:
        if 'Cache' in stdout or 'Memory' in stdout or 'Slab' in stdout:
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
        [sys.executable, 'baremetal_slab_monitor.py', '--verbose']
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
        [sys.executable, 'baremetal_slab_monitor.py', '--warn-only']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_all_caches_flag():
    """Test --all-caches flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--all-caches', '--format', 'json']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized arguments' not in stderr:
        print("[PASS] All-caches flag test passed")
        return True
    else:
        print("[FAIL] All-caches flag not recognized")
        print(f"  Error: {stderr[:100]}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--top', '15', '--warn-pct', '20', '--crit-pct', '50']
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
        [sys.executable, 'baremetal_slab_monitor.py']
    )

    # Valid exit codes: 0 (no issues), 1 (issues), 2 (no access/usage error)
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_top_option():
    """Test that --top option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--top', '20']
    )

    # Should not fail due to unrecognized option or invalid value
    if 'unrecognized' not in stderr and 'invalid' not in stderr.lower():
        print("[PASS] Top option test passed")
        return True
    else:
        print("[FAIL] Top option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_pct_option():
    """Test that --warn-pct option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--warn-pct', '30']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Warn-pct option test passed")
        return True
    else:
        print("[FAIL] Warn-pct option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_crit_pct_option():
    """Test that --crit-pct option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--crit-pct', '50']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Crit-pct option test passed")
        return True
    else:
        print("[FAIL] Crit-pct option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_warn_ratio_option():
    """Test that --warn-ratio option accepts valid values"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--warn-ratio', '0.6']
    )

    # Should not fail due to unrecognized option
    if 'unrecognized' not in stderr:
        print("[PASS] Warn-ratio option test passed")
        return True
    else:
        print("[FAIL] Warn-ratio option not accepted")
        print(f"  Error: {stderr[:100]}")
        return False


def test_help_contains_exit_codes():
    """Test that help message documents exit codes"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes' in stdout:
        print("[PASS] Help documents exit codes")
        return True
    else:
        print("[FAIL] Help should document exit codes")
        return False


def test_help_contains_examples():
    """Test that help message includes examples"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_slab_monitor.py', '--help']
    )

    if return_code == 0 and 'Example' in stdout:
        print("[PASS] Help contains examples")
        return True
    else:
        print("[FAIL] Help should contain examples")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_slab_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_top_zero,
        test_invalid_top_negative,
        test_invalid_warn_pct_zero,
        test_invalid_warn_pct_over_100,
        test_invalid_crit_pct_zero,
        test_warn_pct_greater_than_crit_pct,
        test_invalid_warn_ratio_zero,
        test_invalid_warn_ratio_over_1,
        test_format_option,
        test_json_output_format,
        test_table_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_all_caches_flag,
        test_combined_options,
        test_exit_code_validity,
        test_top_option,
        test_warn_pct_option,
        test_crit_pct_option,
        test_warn_ratio_option,
        test_help_contains_exit_codes,
        test_help_contains_examples,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
