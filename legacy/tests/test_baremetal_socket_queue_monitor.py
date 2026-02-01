#!/usr/bin/env python3
"""
Test script for baremetal_socket_queue_monitor.py functionality.
Tests argument parsing and error handling without requiring elevated privileges.
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
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--help']
    )

    if return_code == 0 and 'socket' in stdout.lower() and 'queue' in stdout.lower():
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
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_plain():
    """Test that plain format option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--format', 'plain']
    )

    # Should either work or fail gracefully
    if return_code in [0, 1, 2]:
        if 'invalid choice' not in stderr:
            print("[PASS] Plain format option test passed")
            return True

    print("[FAIL] Plain format option test failed")
    print(f"  Error: {stderr[:100]}")
    return False


def test_format_option_json():
    """Test JSON output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--format', 'json']
    )

    # If it works, validate JSON structure
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'issues' in data and 'summary' in data:
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
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--format', 'table']
    )

    if return_code in [0, 1, 2]:
        if 'invalid choice' not in stderr:
            print("[PASS] Table format option test passed")
            return True

    print("[FAIL] Table format option test failed")
    return False


def test_verbose_flag():
    """Test verbose flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--verbose']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Verbose flag test passed")
        return True
    else:
        print("[FAIL] Verbose flag not recognized")
        return False


def test_warn_only_flag():
    """Test warn-only flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        return False


def test_protocol_tcp():
    """Test TCP protocol option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--protocol', 'tcp']
    )

    if return_code in [0, 1, 2] and 'invalid choice' not in stderr:
        print("[PASS] Protocol TCP option test passed")
        return True

    print("[FAIL] Protocol TCP option test failed")
    return False


def test_protocol_udp():
    """Test UDP protocol option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--protocol', 'udp']
    )

    if return_code in [0, 1, 2] and 'invalid choice' not in stderr:
        print("[PASS] Protocol UDP option test passed")
        return True

    print("[FAIL] Protocol UDP option test failed")
    return False


def test_protocol_all():
    """Test all protocol option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--protocol', 'all']
    )

    if return_code in [0, 1, 2] and 'invalid choice' not in stderr:
        print("[PASS] Protocol all option test passed")
        return True

    print("[FAIL] Protocol all option test failed")
    return False


def test_invalid_protocol():
    """Test that invalid protocol is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--protocol', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid protocol test passed")
        return True
    else:
        print("[FAIL] Invalid protocol should be rejected")
        return False


def test_recv_warn_option():
    """Test receive warning threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--recv-warn', '65536']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Recv-warn option test passed")
        return True
    else:
        print("[FAIL] Recv-warn option not recognized")
        return False


def test_recv_crit_option():
    """Test receive critical threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--recv-crit', '1048576']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Recv-crit option test passed")
        return True
    else:
        print("[FAIL] Recv-crit option not recognized")
        return False


def test_send_warn_option():
    """Test send warning threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--send-warn', '65536']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Send-warn option test passed")
        return True
    else:
        print("[FAIL] Send-warn option not recognized")
        return False


def test_send_crit_option():
    """Test send critical threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--send-crit', '1048576']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Send-crit option test passed")
        return True
    else:
        print("[FAIL] Send-crit option not recognized")
        return False


def test_listen_warn_option():
    """Test listen backlog warning threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--listen-warn', '64']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Listen-warn option test passed")
        return True
    else:
        print("[FAIL] Listen-warn option not recognized")
        return False


def test_listen_crit_option():
    """Test listen backlog critical threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--listen-crit', '512']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Listen-crit option test passed")
        return True
    else:
        print("[FAIL] Listen-crit option not recognized")
        return False


def test_min_queue_option():
    """Test minimum queue threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--min-queue', '512']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Min-queue option test passed")
        return True
    else:
        print("[FAIL] Min-queue option not recognized")
        return False


def test_negative_recv_warn():
    """Test that negative receive warning threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--recv-warn', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative recv-warn test passed")
        return True
    else:
        print(f"[FAIL] Negative recv-warn should return exit code 2, got {return_code}")
        return False


def test_negative_send_warn():
    """Test that negative send warning threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--send-warn', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative send-warn test passed")
        return True
    else:
        print(f"[FAIL] Negative send-warn should return exit code 2, got {return_code}")
        return False


def test_negative_listen_warn():
    """Test that negative listen warning threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--listen-warn', '-10']
    )

    if return_code == 2:
        print("[PASS] Negative listen-warn test passed")
        return True
    else:
        print(f"[FAIL] Negative listen-warn should return exit code 2, got {return_code}")
        return False


def test_negative_min_queue():
    """Test that negative min-queue is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--min-queue', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative min-queue test passed")
        return True
    else:
        print(f"[FAIL] Negative min-queue should return exit code 2, got {return_code}")
        return False


def test_warn_exceeds_crit_recv():
    """Test that recv warning exceeding critical is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py',
         '--recv-warn', '1000000', '--recv-crit', '100000']
    )

    if return_code == 2:
        print("[PASS] Recv warn > crit test passed")
        return True
    else:
        print(f"[FAIL] Recv warn > crit should return exit code 2, got {return_code}")
        return False


def test_warn_exceeds_crit_send():
    """Test that send warning exceeding critical is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py',
         '--send-warn', '1000000', '--send-crit', '100000']
    )

    if return_code == 2:
        print("[PASS] Send warn > crit test passed")
        return True
    else:
        print(f"[FAIL] Send warn > crit should return exit code 2, got {return_code}")
        return False


def test_warn_exceeds_crit_listen():
    """Test that listen warning exceeding critical is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py',
         '--listen-warn', '1000', '--listen-crit', '100']
    )

    if return_code == 2:
        print("[PASS] Listen warn > crit test passed")
        return True
    else:
        print(f"[FAIL] Listen warn > crit should return exit code 2, got {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--protocol', 'tcp', '--recv-warn', '65536', '--send-warn', '65536']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed with code {return_code}")
        return False


def test_exit_code_validity():
    """Test that exit codes are valid (0, 1, or 2)"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Exit code validity test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_json_structure():
    """Test JSON output has expected structure"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_socket_queue_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            required_keys = ['issues', 'summary']
            if all(k in data for k in required_keys):
                if 'critical' in data['issues'] and 'warning' in data['issues']:
                    print("[PASS] JSON structure test passed")
                    return True
        except json.JSONDecodeError:
            pass

    # Exit 2 is acceptable for system access issues
    if return_code == 2:
        print("[PASS] JSON structure test passed (system access limited)")
        return True

    print(f"[FAIL] JSON structure test failed")
    return False


if __name__ == "__main__":
    print(f"Testing baremetal_socket_queue_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_verbose_flag,
        test_warn_only_flag,
        test_protocol_tcp,
        test_protocol_udp,
        test_protocol_all,
        test_invalid_protocol,
        test_recv_warn_option,
        test_recv_crit_option,
        test_send_warn_option,
        test_send_crit_option,
        test_listen_warn_option,
        test_listen_crit_option,
        test_min_queue_option,
        test_negative_recv_warn,
        test_negative_send_warn,
        test_negative_listen_warn,
        test_negative_min_queue,
        test_warn_exceeds_crit_recv,
        test_warn_exceeds_crit_send,
        test_warn_exceeds_crit_listen,
        test_combined_options,
        test_exit_code_validity,
        test_json_structure,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
