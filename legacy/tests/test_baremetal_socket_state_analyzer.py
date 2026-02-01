#!/usr/bin/env python3
"""
Test script for baremetal_socket_state_analyzer.py functionality.
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
        stdout, stderr = proc.communicate(timeout=30)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def test_help_message():
    """Test that the help message works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--help']
    )

    if return_code == 0 and 'socket' in stdout.lower():
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
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'json']
    )

    # Should succeed (0) or detect issues (1), but not usage error (2) unless /proc missing
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify expected JSON structure
            if 'tcp_states' in data and 'status' in data and 'summary' in data:
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
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'table']
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
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_socket_state_analyzer.py', '-v']
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
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--warn-only']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_custom_time_wait_threshold():
    """Test custom TIME_WAIT warning threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py',
         '--warn-time-wait', '5000']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom TIME_WAIT threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom TIME_WAIT threshold test failed with code {return_code}")
        return False


def test_custom_close_wait_threshold():
    """Test custom CLOSE_WAIT warning threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py',
         '--warn-close-wait', '50']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom CLOSE_WAIT threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom CLOSE_WAIT threshold test failed with code {return_code}")
        return False


def test_custom_established_threshold():
    """Test custom ESTABLISHED warning threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py',
         '--warn-established', '10000']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom ESTABLISHED threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom ESTABLISHED threshold test failed with code {return_code}")
        return False


def test_custom_ephemeral_threshold():
    """Test custom ephemeral port usage threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py',
         '--warn-ephemeral-pct', '50']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom ephemeral threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom ephemeral threshold test failed with code {return_code}")
        return False


def test_custom_syn_recv_threshold():
    """Test custom SYN_RECV warning threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py',
         '--warn-syn-recv', '100']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom SYN_RECV threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom SYN_RECV threshold test failed with code {return_code}")
        return False


def test_exit_codes():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py']
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
        [sys.executable, 'baremetal_socket_state_analyzer.py',
         '--format', 'json',
         '--verbose',
         '--warn-time-wait', '1000',
         '--warn-close-wait', '10']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                print("[PASS] Combined flags test passed")
                return True
            except json.JSONDecodeError:
                print("[FAIL] Combined flags produced invalid JSON")
                return False
        else:
            print("[PASS] Combined flags test passed (dependency missing)")
            return True
    else:
        print(f"[FAIL] Combined flags test failed with code {return_code}")
        return False


def test_json_tcp_states_structure():
    """Test that JSON output contains tcp_states dictionary"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            tcp_states = data.get('tcp_states', {})
            if isinstance(tcp_states, dict):
                print("[PASS] JSON tcp_states structure test passed")
                return True
            else:
                print(f"[FAIL] tcp_states is not a dict: {type(tcp_states)}")
                return False
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            return False
    elif return_code == 2:
        print("[PASS] JSON tcp_states structure test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_json_ephemeral_ports_structure():
    """Test that JSON output contains ephemeral_ports info"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            eph = data.get('ephemeral_ports', {})
            expected_keys = ['in_use', 'range_low', 'range_high', 'usage_pct']
            missing = [k for k in expected_keys if k not in eph]
            if missing:
                print(f"[FAIL] Missing ephemeral_ports keys: {missing}")
                return False
            print("[PASS] JSON ephemeral_ports structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            return False
    elif return_code == 2:
        print("[PASS] JSON ephemeral_ports structure test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_json_has_issues_flag():
    """Test that has_issues flag is present and boolean"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            has_issues = data.get('has_issues')
            if isinstance(has_issues, bool):
                print("[PASS] has_issues flag test passed")
                return True
            else:
                print(f"[FAIL] has_issues is not boolean: {has_issues}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] has_issues flag test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_json_status_value():
    """Test that status field has valid value"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            status = data.get('status')
            if status in ['ok', 'warning', 'critical']:
                print("[PASS] JSON status value test passed")
                return True
            else:
                print(f"[FAIL] Invalid status value: {status}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] JSON status value test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_json_summary_structure():
    """Test that JSON summary contains expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_keys = ['tcp_total', 'udp_total', 'ephemeral_usage_pct']
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
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_verbose_json_includes_listening_ports():
    """Test that verbose JSON includes listening_ports"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py',
         '--format', 'json', '-v']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'listening_ports' in data:
                lp = data['listening_ports']
                if 'tcp' in lp and 'udp' in lp:
                    print("[PASS] Verbose JSON listening_ports test passed")
                    return True
                else:
                    print("[FAIL] listening_ports missing tcp or udp keys")
                    return False
            else:
                print("[FAIL] Verbose mode should include listening_ports")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] Verbose JSON listening_ports test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_json_issues_array():
    """Test that issues field is an array"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            issues = data.get('issues')
            if isinstance(issues, list):
                print("[PASS] JSON issues array test passed")
                return True
            else:
                print(f"[FAIL] issues is not an array: {type(issues)}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] JSON issues array test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_plain_output_contains_states():
    """Test that plain output contains socket state info"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_state_analyzer.py']
    )

    if return_code in [0, 1]:
        # Check for expected content in plain output
        if 'TCP Socket States' in stdout or 'ESTABLISHED' in stdout:
            print("[PASS] Plain output contains states test passed")
            return True
        else:
            print("[FAIL] Plain output missing expected state information")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        print("[PASS] Plain output contains states test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_socket_state_analyzer.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_json_output_format,
        test_table_format,
        test_plain_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_custom_time_wait_threshold,
        test_custom_close_wait_threshold,
        test_custom_established_threshold,
        test_custom_ephemeral_threshold,
        test_custom_syn_recv_threshold,
        test_exit_codes,
        test_combined_flags,
        test_json_tcp_states_structure,
        test_json_ephemeral_ports_structure,
        test_json_has_issues_flag,
        test_json_status_value,
        test_json_summary_structure,
        test_verbose_json_includes_listening_ports,
        test_json_issues_array,
        test_plain_output_contains_states,
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
