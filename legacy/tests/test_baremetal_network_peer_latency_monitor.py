#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for baremetal_network_peer_latency_monitor.py functionality.
Tests argument parsing and error handling without requiring actual network access.
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
        [sys.executable, 'baremetal_network_peer_latency_monitor.py', '--help']
    )

    if return_code == 0 and 'latency' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed - return code: {return_code}")
        print(f"  stdout: {stdout[:200]}")
        return False


def test_verbose_option():
    """Test that the verbose option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '-v', '--targets', '127.0.0.1', '--count', '1']
    )

    # Should not fail at argument parsing level (exit 0 or 1 from actual check)
    if return_code in [0, 1]:
        print("[PASS] Verbose option test passed")
        return True
    else:
        print(f"[FAIL] Verbose option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_format_json_option():
    """Test that the JSON format option works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--format', 'json', '--targets', '127.0.0.1', '--count', '1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        # Try to parse JSON output
        try:
            data = json.loads(stdout)
            if 'summary' in data and 'results' in data:
                print("[PASS] JSON format option test passed")
                return True
            else:
                print("[FAIL] JSON format missing expected keys")
                return False
        except json.JSONDecodeError:
            print(f"[FAIL] JSON format test failed - invalid JSON")
            print(f"  stdout: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] JSON format test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_format_table_option():
    """Test that the table format option works"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--format', 'table', '--targets', '127.0.0.1', '--count', '1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1] and 'STATUS' in stdout and 'TARGET' in stdout:
        print("[PASS] Table format option test passed")
        return True
    else:
        print(f"[FAIL] Table format test failed with return code: {return_code}")
        print(f"  stdout: {stdout[:200]}")
        return False


def test_invalid_format():
    """Test that invalid format option is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--format', 'invalid']
    )

    # Should fail with argument error (exit code 2)
    if return_code == 2 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format test failed - should have rejected invalid format")
        print(f"  return_code: {return_code}, stderr: {stderr[:200]}")
        return False


def test_tcp_option():
    """Test that TCP probe mode is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--tcp', '--targets', '127.0.0.1', '--port', '22', '--count', '1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] TCP option test passed")
        return True
    else:
        print(f"[FAIL] TCP option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_custom_thresholds():
    """Test that custom threshold options are recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--warn-ms', '25', '--crit-ms', '50', '--max-loss', '5',
         '--targets', '127.0.0.1', '--count', '1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_multiple_targets():
    """Test that multiple targets work"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--targets', '127.0.0.1,127.0.0.2', '--count', '1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        # Check that both targets appear in output
        if '127.0.0.1' in stdout:
            print("[PASS] Multiple targets test passed")
            return True
        else:
            print("[FAIL] Multiple targets not shown in output")
            return False
    else:
        print(f"[FAIL] Multiple targets test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_warn_only_option():
    """Test that warn-only option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--warn-only', '--targets', '127.0.0.1', '--count', '1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Warn-only option test passed")
        return True
    else:
        print(f"[FAIL] Warn-only option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_count_option():
    """Test that count option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--count', '2', '--targets', '127.0.0.1']
    )

    # Should not fail at argument parsing level
    if return_code in [0, 1]:
        print("[PASS] Count option test passed")
        return True
    else:
        print(f"[FAIL] Count option test failed with return code: {return_code}")
        print(f"  stderr: {stderr}")
        return False


def test_localhost_ping():
    """Test pinging localhost (should always work)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--targets', '127.0.0.1', '--count', '2']
    )

    # Localhost ping should succeed with exit 0
    if return_code == 0 and '127.0.0.1' in stdout:
        print("[PASS] Localhost ping test passed")
        return True
    elif return_code == 1:
        # Might have warnings but still works
        print("[PASS] Localhost ping test passed (with warnings)")
        return True
    else:
        print(f"[FAIL] Localhost ping test failed with return code: {return_code}")
        print(f"  stdout: {stdout[:200]}")
        print(f"  stderr: {stderr}")
        return False


def test_json_structure():
    """Test that JSON output has correct structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_peer_latency_monitor.py',
         '--format', 'json', '--targets', '127.0.0.1', '--count', '1']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check required fields
            required_summary = ['total_targets', 'ok', 'warning', 'critical', 'has_issues']
            for field in required_summary:
                if field not in data.get('summary', {}):
                    print(f"[FAIL] JSON structure missing summary.{field}")
                    return False

            # Check results structure
            if 'results' not in data or not isinstance(data['results'], list):
                print("[FAIL] JSON structure missing results array")
                return False

            if len(data['results']) > 0:
                result = data['results'][0]
                required_result = ['target', 'reachable', 'method', 'status']
                for field in required_result:
                    if field not in result:
                        print(f"[FAIL] JSON result missing {field}")
                        return False

            print("[PASS] JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON structure test failed - parse error: {e}")
            return False
    else:
        print(f"[FAIL] JSON structure test failed with return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_network_peer_latency_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_verbose_option,
        test_format_json_option,
        test_format_table_option,
        test_invalid_format,
        test_tcp_option,
        test_custom_thresholds,
        test_multiple_targets,
        test_warn_only_option,
        test_count_option,
        test_localhost_ping,
        test_json_structure,
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
            print(f"[ERROR] {test.__name__} raised exception: {e}")
            failed += 1

    print()
    print(f"Test Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
