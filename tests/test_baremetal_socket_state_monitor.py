#!/usr/bin/env python3
"""
Test script for baremetal_socket_state_monitor.py functionality.
Tests argument parsing and error handling without requiring specific socket states.
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
        [sys.executable, 'baremetal_socket_state_monitor.py', '--help']
    )

    if return_code == 0 and 'socket state' in stdout.lower():
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
        [sys.executable, 'baremetal_socket_state_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_socket_state_monitor.py', '--format', 'json']
    )

    # Should succeed (0) or detect issues (1), but not usage error (2)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify expected JSON structure
            if 'state_counts' in data and 'issues' in data and 'total_sockets' in data:
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
        [sys.executable, 'baremetal_socket_state_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_socket_state_monitor.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_socket_state_monitor.py', '-v']
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
        [sys.executable, 'baremetal_socket_state_monitor.py', '--warn-only']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False

def test_custom_thresholds():
    """Test custom threshold arguments"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_monitor.py',
         '--time-wait', '2000',
         '--close-wait', '200',
         '--syn-recv', '50',
         '--established', '10000',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed with code {return_code}")
        return False

def test_exit_codes():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_monitor.py']
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
        [sys.executable, 'baremetal_socket_state_monitor.py',
         '--format', 'json',
         '--verbose',
         '--warn-only',
         '--time-wait', '1500']
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

if __name__ == "__main__":
    print(f"Testing baremetal_socket_state_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_json_output_format,
        test_table_format,
        test_plain_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_custom_thresholds,
        test_exit_codes,
        test_combined_flags
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
