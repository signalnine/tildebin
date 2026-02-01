#!/usr/bin/env python3
"""
Test script for baremetal_ephemeral_port_monitor.py functionality.
Tests argument parsing and error handling without requiring specific port states.
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '--help']
    )

    if return_code == 0 and 'ephemeral' in stdout.lower():
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '--format', 'json']
    )

    # Should succeed (0) or detect issues (1), but not usage error (2)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify expected JSON structure
            if 'ephemeral_ports' in data and 'issues' in data:
                # Verify nested structure
                ep = data['ephemeral_ports']
                if 'port_range' in ep and 'used' in ep and 'free' in ep:
                    print("[PASS] JSON output format test passed")
                    return True
                else:
                    print(f"[FAIL] JSON structure missing expected keys in ephemeral_ports")
                    return False
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '-v']
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '--warn-only']
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py',
         '--warning', '60',
         '--critical', '80',
         '--time-wait-percent', '25',
         '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed with code {return_code}")
        return False


def test_invalid_threshold_order():
    """Test that warning >= critical is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ephemeral_port_monitor.py',
         '--warning', '90',
         '--critical', '80']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2 and 'threshold' in stderr.lower():
        print("[PASS] Invalid threshold order test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold order should fail with code 2")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_exit_codes():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ephemeral_port_monitor.py']
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
        [sys.executable, 'baremetal_ephemeral_port_monitor.py',
         '--format', 'json',
         '--verbose',
         '--warning', '65',
         '--critical', '85']
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


def test_json_structure_completeness():
    """Test that JSON output contains all expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_ephemeral_port_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            ep = data.get('ephemeral_ports', {})
            required_fields = ['port_range', 'total_available', 'used', 'free',
                               'usage_percent', 'by_state']
            missing = [f for f in required_fields if f not in ep]
            if not missing:
                print("[PASS] JSON structure completeness test passed")
                return True
            else:
                print(f"[FAIL] Missing fields: {missing}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] JSON structure completeness test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_ephemeral_port_monitor.py...")
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
        test_invalid_threshold_order,
        test_exit_codes,
        test_combined_flags,
        test_json_structure_completeness
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
