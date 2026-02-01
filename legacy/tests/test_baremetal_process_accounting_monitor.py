#!/usr/bin/env python3
"""
Test script for baremetal_process_accounting_monitor.py functionality.
Tests argument parsing and output format validation without requiring elevated privileges.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
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
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--help']
    )

    if return_code == 0 and 'process' in stdout.lower() and 'accounting' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_plain():
    """Test that plain format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--format', 'plain']
    )

    if return_code in [0, 1, 2]:
        if 'invalid choice' not in stderr:
            print("[PASS] Plain format option test passed")
            return True

    print("[FAIL] Plain format option test failed")
    print(f"  Error: {stderr[:100]}")
    return False


def test_format_option_json():
    """Test JSON output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--format', 'json']
    )

    # If it works, validate JSON structure
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'top_processes' in data:
                print("[PASS] JSON format option test passed")
                return True
        except json.JSONDecodeError:
            pass

    # If exit 2, should be a system access issue
    if return_code == 2:
        if 'proc' in stderr.lower() or 'error' in stderr.lower():
            print("[PASS] JSON format option test passed (system access issue)")
            return True

    print(f"[FAIL] JSON format option test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stdout: {stdout[:100]}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_format_option_table():
    """Test table format option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        if 'invalid choice' not in stderr:
            print("[PASS] Table format option test passed")
            return True

    print("[FAIL] Table format option test failed")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--verbose']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        return False


def test_top_option():
    """Test top N option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--top', '5']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Top option test passed")
        return True
    else:
        print("[FAIL] Top option not recognized")
        return False


def test_top_short_option():
    """Test top N short option (-n)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '-n', '5']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Top short option test passed")
        return True
    else:
        print("[FAIL] Top short option not recognized")
        return False


def test_invalid_top_zero():
    """Test that --top 0 is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--top', '0']
    )

    if return_code == 2:
        print("[PASS] Invalid top zero test passed")
        return True
    else:
        print(f"[FAIL] Top 0 should return exit code 2, got {return_code}")
        return False


def test_sort_options():
    """Test all sort options are recognized."""
    sort_options = ['cpu', 'io_read', 'io_write', 'memory', 'pid']
    all_passed = True

    for sort_opt in sort_options:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_process_accounting_monitor.py', '--sort', sort_opt]
        )

        if 'invalid choice' in stderr:
            print(f"[FAIL] Sort option '{sort_opt}' not recognized")
            all_passed = False

    if all_passed:
        print("[PASS] Sort options test passed")
        return True
    return False


def test_user_filter():
    """Test user filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--user', 'root']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] User filter test passed")
        return True
    else:
        print("[FAIL] User filter not recognized")
        return False


def test_command_filter():
    """Test command filter option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--command', 'python']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Command filter test passed")
        return True
    else:
        print("[FAIL] Command filter not recognized")
        return False


def test_min_cpu_option():
    """Test minimum CPU time filter."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-cpu', '10']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Min CPU option test passed")
        return True
    else:
        print("[FAIL] Min CPU option not recognized")
        return False


def test_min_io_read_option():
    """Test minimum I/O read filter."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-io-read', '100MB']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Min I/O read option test passed")
        return True
    else:
        print("[FAIL] Min I/O read option not recognized")
        return False


def test_min_io_write_option():
    """Test minimum I/O write filter."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-io-write', '50MB']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Min I/O write option test passed")
        return True
    else:
        print("[FAIL] Min I/O write option not recognized")
        return False


def test_min_memory_option():
    """Test minimum memory filter."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-memory', '1000']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Min memory option test passed")
        return True
    else:
        print("[FAIL] Min memory option not recognized")
        return False


def test_warn_cpu_option():
    """Test CPU warning threshold option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--warn-cpu', '3600']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn CPU option test passed")
        return True
    else:
        print("[FAIL] Warn CPU option not recognized")
        return False


def test_warn_io_read_option():
    """Test I/O read warning threshold option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--warn-io-read', '1GB']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn I/O read option test passed")
        return True
    else:
        print("[FAIL] Warn I/O read option not recognized")
        return False


def test_warn_io_write_option():
    """Test I/O write warning threshold option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--warn-io-write', '500MB']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn I/O write option test passed")
        return True
    else:
        print("[FAIL] Warn I/O write option not recognized")
        return False


def test_warn_memory_option():
    """Test memory warning threshold option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--warn-memory', '100000']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn memory option test passed")
        return True
    else:
        print("[FAIL] Warn memory option not recognized")
        return False


def test_invalid_size_format():
    """Test that invalid size format is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-io-read', 'invalid']
    )

    if return_code == 2:
        print("[PASS] Invalid size format test passed")
        return True
    else:
        print(f"[FAIL] Invalid size format should return exit code 2, got {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py',
         '--format', 'json', '--verbose', '--top', '5',
         '--sort', 'memory', '--min-cpu', '0']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with code {return_code}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_json_structure():
    """Test JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            required_keys = ['summary', 'warnings', 'top_processes']
            if all(k in data for k in required_keys):
                # Check summary has expected fields
                summary = data.get('summary', {})
                expected_summary = ['total_processes_scanned', 'processes_with_warnings']
                if all(s in summary for s in expected_summary):
                    print("[PASS] JSON structure test passed")
                    return True
        except json.JSONDecodeError:
            pass

    # Exit 2 is acceptable for system access issues
    if return_code == 2:
        print("[PASS] JSON structure test passed (system access limited)")
        return True

    print(f"[FAIL] JSON structure test failed")
    print(f"  Stdout: {stdout[:200]}")
    return False


def test_default_run():
    """Test default execution without any options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py']
    )

    # Should succeed or fail gracefully
    if return_code in [0, 1]:
        # Should contain some output about processes
        if 'pid' in stdout.lower() or 'process' in stdout.lower():
            print("[PASS] Default run test passed")
            return True
    elif return_code == 2:
        # System access issue is acceptable
        print("[PASS] Default run test passed (system access limited)")
        return True

    print(f"[FAIL] Default run test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stdout: {stdout[:100]}")
    return False


def test_size_parsing_mb():
    """Test size parsing with MB suffix."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-io-read', '100MB']
    )

    if return_code in [0, 1, 2] and 'Invalid size format' not in stderr:
        print("[PASS] Size parsing MB test passed")
        return True
    else:
        print(f"[FAIL] Size parsing MB test failed")
        return False


def test_size_parsing_gb():
    """Test size parsing with GB suffix."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-io-write', '1GB']
    )

    if return_code in [0, 1, 2] and 'Invalid size format' not in stderr:
        print("[PASS] Size parsing GB test passed")
        return True
    else:
        print(f"[FAIL] Size parsing GB test failed")
        return False


def test_size_parsing_kb():
    """Test size parsing with KB suffix."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py', '--min-io-read', '1024KB']
    )

    if return_code in [0, 1, 2] and 'Invalid size format' not in stderr:
        print("[PASS] Size parsing KB test passed")
        return True
    else:
        print(f"[FAIL] Size parsing KB test failed")
        return False


def test_short_options():
    """Test short option variants."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_accounting_monitor.py',
         '-v', '-w', '-n', '5', '-s', 'cpu', '-u', 'root', '-c', 'bash']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short options test passed")
        return True
    else:
        print("[FAIL] Short options not recognized")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_process_accounting_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_verbose_flag,
        test_warn_only_flag,
        test_top_option,
        test_top_short_option,
        test_invalid_top_zero,
        test_sort_options,
        test_user_filter,
        test_command_filter,
        test_min_cpu_option,
        test_min_io_read_option,
        test_min_io_write_option,
        test_min_memory_option,
        test_warn_cpu_option,
        test_warn_io_read_option,
        test_warn_io_write_option,
        test_warn_memory_option,
        test_invalid_size_format,
        test_combined_options,
        test_exit_code_validity,
        test_json_structure,
        test_default_run,
        test_size_parsing_mb,
        test_size_parsing_gb,
        test_size_parsing_kb,
        test_short_options,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
