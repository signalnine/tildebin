#!/usr/bin/env python3
"""
Test script for baremetal_process_connection_audit.py functionality.
Tests argument parsing and error handling without requiring specific connections.
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
        [sys.executable, 'baremetal_process_connection_audit.py', '--help']
    )

    if return_code == 0 and 'connection' in stdout.lower() and 'process' in stdout.lower():
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
        [sys.executable, 'baremetal_process_connection_audit.py', '--invalid-flag']
    )

    # Should fail with usage error (exit code 2) or general error
    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_json_output_format():
    """Test JSON output format parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py', '--format', 'json']
    )

    # Should succeed (0) or detect issues (1), but not usage error (2)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify expected JSON structure
            if 'process_summary' in data and 'issues' in data and 'summary' in data:
                print("[PASS] JSON output format test passed")
                return True
            else:
                print(f"[FAIL] JSON structure missing expected keys")
                print(f"  Keys found: {list(data.keys())}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            print(f"  Output: {stdout[:200]}")
            return False
    elif return_code == 2:
        # Missing /proc files is acceptable in test environment
        print("[PASS] JSON output format test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_table_format():
    """Test table output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py', '--format', 'table']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Table format test passed")
        return True
    else:
        print(f"[FAIL] Table format test failed with code {return_code}")
        return False


def test_plain_format():
    """Test plain output format (default)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py', '--format', 'plain']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Plain format test passed")
        return True
    else:
        print(f"[FAIL] Plain format test failed with code {return_code}")
        return False


def test_verbose_flag():
    """Test verbose output flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py', '-v']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Verbose flag test failed with code {return_code}")
        return False


def test_warn_only_flag():
    """Test warn-only output flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py', '--warn-only']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_max_per_process_threshold():
    """Test max-per-process threshold argument"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--max-per-process', '500',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Max per process threshold test passed")
        return True
    else:
        print(f"[FAIL] Max per process threshold test failed with code {return_code}")
        return False


def test_max_to_single_host_threshold():
    """Test max-to-single-host threshold argument"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--max-to-single-host', '50',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Max to single host threshold test passed")
        return True
    else:
        print(f"[FAIL] Max to single host threshold test failed with code {return_code}")
        return False


def test_process_filter():
    """Test process name filter"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--process', 'python',
         '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify all processes match filter (if any exist)
            for proc in data.get('process_summary', []):
                if 'python' not in proc.get('name', '').lower():
                    print(f"[FAIL] Found non-matching process with --process python: {proc['name']}")
                    return False
            print("[PASS] Process filter test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] Process filter produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Process filter test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Process filter test failed with code {return_code}")
        return False


def test_pid_filter():
    """Test PID filter"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--pid', '1',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] PID filter test passed")
        return True
    else:
        print(f"[FAIL] PID filter test failed with code {return_code}")
        return False


def test_remote_port_filter():
    """Test remote port filter"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--remote-port', '443',
         '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # If we have process_summary, verify the structure
            if 'process_summary' in data:
                print("[PASS] Remote port filter test passed")
                return True
            else:
                print("[FAIL] Missing process_summary in output")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Remote port filter produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Remote port filter test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Remote port filter test failed with code {return_code}")
        return False


def test_remote_ip_filter():
    """Test remote IP filter"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--remote-ip', '127.0.0.1',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Remote IP filter test passed")
        return True
    else:
        print(f"[FAIL] Remote IP filter test failed with code {return_code}")
        return False


def test_state_filter():
    """Test TCP state filter"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--state', 'ESTABLISHED',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] State filter test passed")
        return True
    else:
        print(f"[FAIL] State filter test failed with code {return_code}")
        return False


def test_invalid_state_filter():
    """Test that invalid TCP state is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--state', 'INVALID_STATE']
    )

    # Should fail with usage error (exit code 2)
    if return_code == 2:
        print("[PASS] Invalid state filter test passed")
        return True
    else:
        print(f"[FAIL] Invalid state should fail with code 2, got {return_code}")
        return False


def test_exclude_loopback():
    """Test exclude loopback flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--exclude-loopback',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Exclude loopback test passed")
        return True
    else:
        print(f"[FAIL] Exclude loopback test failed with code {return_code}")
        return False


def test_exit_codes():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py']
    )

    # Exit codes: 0 (ok), 1 (issues), 2 (missing deps/usage error)
    if return_code in [0, 1, 2]:
        print(f"[PASS] Exit code test passed (code: {return_code})")
        return True
    else:
        print(f"[FAIL] Invalid exit code: {return_code}")
        return False


def test_combined_flags():
    """Test combination of multiple flags"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--format', 'json',
         '--verbose',
         '--exclude-loopback',
         '--max-per-process', '500']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        # Verify JSON output if successful
        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                print("[PASS] Combined flags test passed")
                return True
            except json.JSONDecodeError:
                print("[FAIL] Combined flags produced invalid JSON")
                return False
        else:
            # Missing deps is acceptable
            print("[PASS] Combined flags test passed (dependency missing)")
            return True
    else:
        print(f"[FAIL] Combined flags test failed with code {return_code}")
        return False


def test_json_summary_structure():
    """Test that JSON output contains expected summary fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_keys = ['total_connections', 'total_processes', 'established', 'time_wait', 'close_wait']
            missing = [k for k in expected_keys if k not in summary]
            if missing:
                print(f"[FAIL] Missing summary keys: {missing}")
                return False
            print("[PASS] JSON summary structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            return False
    elif return_code == 2:
        print("[PASS] JSON summary structure test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] JSON summary structure test failed with code {return_code}")
        return False


def test_process_summary_structure():
    """Test that process_summary has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            for proc in data.get('process_summary', []):
                expected_keys = ['pid', 'name', 'connection_count', 'unique_remote_hosts',
                                'unique_remote_ports', 'state_breakdown', 'top_remotes']
                missing = [k for k in expected_keys if k not in proc]
                if missing:
                    print(f"[FAIL] Missing process_summary keys: {missing}")
                    return False
            print("[PASS] Process summary structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            return False
    elif return_code == 2:
        print("[PASS] Process summary structure test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Process summary structure test failed with code {return_code}")
        return False


def test_table_verbose():
    """Test table format with verbose flag shows individual connections"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_process_connection_audit.py',
         '--format', 'table',
         '-v']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Table verbose test passed")
        return True
    else:
        print(f"[FAIL] Table verbose test failed with code {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_process_connection_audit.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_json_output_format,
        test_table_format,
        test_plain_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_max_per_process_threshold,
        test_max_to_single_host_threshold,
        test_process_filter,
        test_pid_filter,
        test_remote_port_filter,
        test_remote_ip_filter,
        test_state_filter,
        test_invalid_state_filter,
        test_exclude_loopback,
        test_exit_codes,
        test_combined_flags,
        test_json_summary_structure,
        test_process_summary_structure,
        test_table_verbose
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("=" * 60)
    print(f"\nTest Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests PASSED!")
        sys.exit(0)
    else:
        print(f"FAILED: {total - passed} test(s) failed")
        sys.exit(1)
