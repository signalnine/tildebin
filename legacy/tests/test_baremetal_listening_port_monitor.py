#!/usr/bin/env python3
"""
Test script for baremetal_listening_port_monitor.py functionality.
Tests argument parsing and error handling without requiring specific listening ports.
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '--help']
    )

    if return_code == 0 and 'listening port' in stdout.lower():
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '--format', 'json']
    )

    # Should succeed (0) or detect issues (1), but not usage error (2)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify expected JSON structure
            if 'listening_ports' in data and 'issues' in data and 'summary' in data:
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '-v']
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '--warn-only']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False

def test_tcp_only_flag():
    """Test TCP-only filter flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py', '--tcp-only', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify all ports are TCP
            for port in data.get('listening_ports', []):
                if not port['protocol'].startswith('tcp'):
                    print(f"[FAIL] Found non-TCP port with --tcp-only: {port['protocol']}")
                    return False
            print("[PASS] TCP-only flag test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] TCP-only flag produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] TCP-only flag test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] TCP-only flag test failed with code {return_code}")
        return False

def test_udp_only_flag():
    """Test UDP-only filter flag"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py', '--udp-only', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify all ports are UDP
            for port in data.get('listening_ports', []):
                if not port['protocol'].startswith('udp'):
                    print(f"[FAIL] Found non-UDP port with --udp-only: {port['protocol']}")
                    return False
            print("[PASS] UDP-only flag test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] UDP-only flag produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] UDP-only flag test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] UDP-only flag test failed with code {return_code}")
        return False

def test_conflicting_tcp_udp_flags():
    """Test that --tcp-only and --udp-only conflict"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py', '--tcp-only', '--udp-only']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Conflicting TCP/UDP flags test passed")
        return True
    else:
        print(f"[FAIL] Conflicting flags should fail with code 2, got {return_code}")
        return False

def test_expected_ports():
    """Test expected ports argument parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py',
         '--expected', '22,80,443',
         '--format', 'json']
    )

    # Should succeed (0) or have issues (1) or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Expected ports test passed")
        return True
    else:
        print(f"[FAIL] Expected ports test failed with code {return_code}")
        return False

def test_unexpected_ports():
    """Test unexpected ports argument parsing"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py',
         '--unexpected', '23,3389',
         '--format', 'json']
    )

    # Should succeed (0) or have issues (1) or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Unexpected ports test passed")
        return True
    else:
        print(f"[FAIL] Unexpected ports test failed with code {return_code}")
        return False

def test_port_range():
    """Test port range parsing (e.g., 8000-8010)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py',
         '--expected', '8000-8005',
         '--format', 'json']
    )

    # Should succeed (0) or have issues (1) or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Port range test passed")
        return True
    else:
        print(f"[FAIL] Port range test failed with code {return_code}")
        return False

def test_port_filter():
    """Test single port filter"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py',
         '--port', '22',
         '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify all ports match filter
            for port in data.get('listening_ports', []):
                if port['port'] != 22:
                    print(f"[FAIL] Found non-matching port with --port 22: {port['port']}")
                    return False
            print("[PASS] Port filter test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] Port filter produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Port filter test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Port filter test failed with code {return_code}")
        return False

def test_show_all_interfaces():
    """Test show-all-interfaces filter"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py',
         '--show-all-interfaces',
         '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify all ports are bound to all interfaces
            for port in data.get('listening_ports', []):
                if port['bind_type'] != 'all':
                    print(f"[FAIL] Found non-all-interfaces port: {port['bind_type']}")
                    return False
            print("[PASS] Show all interfaces test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] Show all interfaces produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Show all interfaces test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Show all interfaces test failed with code {return_code}")
        return False

def test_exit_codes():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_listening_port_monitor.py']
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
        [sys.executable, 'baremetal_listening_port_monitor.py',
         '--format', 'json',
         '--verbose',
         '--tcp-only',
         '--expected', '22,80']
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
        [sys.executable, 'baremetal_listening_port_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_keys = ['total_ports', 'tcp_ports', 'udp_ports', 'all_interfaces', 'localhost_only', 'issue_count']
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

if __name__ == "__main__":
    print(f"Testing baremetal_listening_port_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_json_output_format,
        test_table_format,
        test_plain_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_tcp_only_flag,
        test_udp_only_flag,
        test_conflicting_tcp_udp_flags,
        test_expected_ports,
        test_unexpected_ports,
        test_port_range,
        test_port_filter,
        test_show_all_interfaces,
        test_exit_codes,
        test_combined_flags,
        test_json_summary_structure
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
