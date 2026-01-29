#!/usr/bin/env python3
"""
Test script for baremetal_process_capabilities_auditor.py functionality.
Tests argument parsing and output formats without requiring root privileges
or specific system state.
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
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--help']
    )

    if return_code == 0 and 'capabilities' in stdout.lower():
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
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_list_caps():
    """Test --list-caps option shows all capabilities."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--list-caps']
    )

    if return_code == 0 and 'CAP_SYS_ADMIN' in stdout and 'CAP_NET_RAW' in stdout:
        print("[PASS] List capabilities test passed")
        return True
    else:
        print(f"[FAIL] List capabilities test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py']
    )

    # Should succeed (exit 0 or 1 depending on system state)
    if return_code in [0, 1] and 'Process Capabilities Audit' in stdout:
        print("[PASS] Plain output format test passed")
        return True
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--format', 'json']
    )

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['summary', 'processes', 'high_risk_capabilities']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify summary structure
        summary = data['summary']
        expected_summary_keys = ['total_privileged_processes', 'processes_with_high_risk',
                                  'unique_capabilities_found']
        if not all(key in summary for key in expected_summary_keys):
            print("[FAIL] JSON summary missing required keys")
            print(f"  Summary keys: {list(summary.keys())}")
            return False

        # Verify processes is a list
        if not isinstance(data['processes'], list):
            print("[FAIL] JSON 'processes' should be an array")
            return False

        # Verify high_risk_capabilities is a list
        if not isinstance(data['high_risk_capabilities'], list):
            print("[FAIL] JSON 'high_risk_capabilities' should be an array")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--format', 'table']
    )

    # Should succeed and contain table headers
    if return_code in [0, 1] and 'PROCESS CAPABILITIES AUDIT' in stdout:
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode includes additional information."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_warn_only_mode():
    """Test warn-only mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--warn-only']
    )

    # Should succeed (exit 0 means no high-risk found)
    if return_code in [0, 1]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_include_root():
    """Test --include-root option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--include-root']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Include-root test passed")
        return True
    else:
        print(f"[FAIL] Include-root test failed")
        print(f"  Return code: {return_code}")
        return False


def test_high_risk_only():
    """Test --high-risk-only option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py', '--high-risk-only']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] High-risk-only test passed")
        return True
    else:
        print(f"[FAIL] High-risk-only test failed")
        print(f"  Return code: {return_code}")
        return False


def test_cap_filter():
    """Test filtering by specific capability."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py',
         '--cap', 'CAP_NET_RAW']
    )

    # Should succeed (may find no processes with CAP_NET_RAW)
    if return_code in [0, 1]:
        print("[PASS] Capability filter test passed")
        return True
    else:
        print(f"[FAIL] Capability filter test failed")
        print(f"  Return code: {return_code}")
        return False


def test_invalid_cap_filter():
    """Test that invalid capability is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py',
         '--cap', 'CAP_INVALID_FAKE']
    )

    if return_code == 2 and 'Unknown capability' in stderr:
        print("[PASS] Invalid capability filter test passed")
        return True
    else:
        print(f"[FAIL] Invalid capability filter test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_user_filter():
    """Test filtering by username."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py',
         '--user', 'nonexistentuser12345']
    )

    # Should succeed with no processes found
    if return_code in [0, 1]:
        print("[PASS] User filter test passed")
        return True
    else:
        print(f"[FAIL] User filter test failed")
        print(f"  Return code: {return_code}")
        return False


def test_comm_filter():
    """Test filtering by process name pattern."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py',
         '--comm', 'python']
    )

    # Should succeed
    if return_code in [0, 1]:
        print("[PASS] Comm filter test passed")
        return True
    else:
        print(f"[FAIL] Comm filter test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py',
         '--format', 'json', '--include-root', '--verbose']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            print("[PASS] Combined options test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] Combined options test - JSON parsing failed")
            return False
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_process_structure():
    """Test that JSON process entries have expected structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_capabilities_auditor.py',
         '--format', 'json', '--include-root']
    )

    try:
        data = json.loads(stdout)
        if data['processes']:
            proc = data['processes'][0]
            expected_keys = ['pid', 'comm', 'user', 'effective_caps',
                            'high_risk_caps', 'cap_count', 'high_risk_count']
            if all(key in proc for key in expected_keys):
                print("[PASS] JSON process structure test passed")
                return True
            else:
                print("[FAIL] JSON process structure missing keys")
                print(f"  Found keys: {list(proc.keys())}")
                return False
        else:
            # No processes found, still valid
            print("[PASS] JSON process structure test passed (no processes)")
            return True
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        print(f"[FAIL] JSON process structure test failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_process_capabilities_auditor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_list_caps,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_include_root,
        test_high_risk_only,
        test_cap_filter,
        test_invalid_cap_filter,
        test_user_filter,
        test_comm_filter,
        test_combined_options,
        test_json_process_structure,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__} raised exception: {e}")
            failed += 1

    print()
    print(f"Test Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
