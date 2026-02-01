#!/usr/bin/env python3
"""
Test script for baremetal_network_qdisc_monitor.py functionality.
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--help']
    )

    if return_code == 0 and 'qdisc' in stdout.lower() and 'drop' in stdout.lower():
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--invalid-flag']
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--format', 'plain']
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--format', 'json']
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

    # If exit 2, should be a tc unavailable issue
    if return_code == 2:
        if 'tc' in stderr.lower() or 'error' in stderr.lower():
            print("[PASS] JSON format option test passed (tc unavailable)")
            return True

    print(f"[FAIL] JSON format option test failed")
    print(f"  Return code: {return_code}")
    print(f"  Stdout: {stdout[:100]}")
    print(f"  Stderr: {stderr[:100]}")
    return False


def test_format_option_table():
    """Test table format option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--format', 'table']
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--verbose']
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--warn-only']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print("[FAIL] Warn-only flag not recognized")
        return False


def test_interface_option():
    """Test interface option is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '-i', 'eth0']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Interface option test passed")
        return True
    else:
        print("[FAIL] Interface option not recognized")
        return False


def test_multiple_interfaces():
    """Test multiple interface options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py',
         '-i', 'eth0', '-i', 'eth1']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Multiple interfaces test passed")
        return True
    else:
        print("[FAIL] Multiple interfaces not recognized")
        return False


def test_include_loopback_flag():
    """Test include-loopback flag is recognized"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--include-loopback']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Include-loopback flag test passed")
        return True
    else:
        print("[FAIL] Include-loopback flag not recognized")
        return False


def test_drop_warn_option():
    """Test drop warning threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--drop-warn', '0.5']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Drop-warn option test passed")
        return True
    else:
        print("[FAIL] Drop-warn option not recognized")
        return False


def test_drop_crit_option():
    """Test drop critical threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--drop-crit', '10.0']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Drop-crit option test passed")
        return True
    else:
        print("[FAIL] Drop-crit option not recognized")
        return False


def test_backlog_warn_option():
    """Test backlog warning threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--backlog-warn', '500']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Backlog-warn option test passed")
        return True
    else:
        print("[FAIL] Backlog-warn option not recognized")
        return False


def test_backlog_crit_option():
    """Test backlog critical threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--backlog-crit', '5000']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Backlog-crit option test passed")
        return True
    else:
        print("[FAIL] Backlog-crit option not recognized")
        return False


def test_min_packets_option():
    """Test minimum packets threshold option"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--min-packets', '500']
    )

    if 'unrecognized arguments' not in stderr:
        print("[PASS] Min-packets option test passed")
        return True
    else:
        print("[FAIL] Min-packets option not recognized")
        return False


def test_negative_drop_warn():
    """Test that negative drop warning threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--drop-warn', '-1']
    )

    if return_code == 2:
        print("[PASS] Negative drop-warn test passed")
        return True
    else:
        print(f"[FAIL] Negative drop-warn should return exit code 2, got {return_code}")
        return False


def test_drop_warn_exceeds_100():
    """Test that drop warning threshold over 100% is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--drop-warn', '101']
    )

    if return_code == 2:
        print("[PASS] Drop-warn > 100% test passed")
        return True
    else:
        print(f"[FAIL] Drop-warn > 100% should return exit code 2, got {return_code}")
        return False


def test_negative_backlog_warn():
    """Test that negative backlog warning threshold is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--backlog-warn', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative backlog-warn test passed")
        return True
    else:
        print(f"[FAIL] Negative backlog-warn should return exit code 2, got {return_code}")
        return False


def test_negative_min_packets():
    """Test that negative min-packets is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--min-packets', '-100']
    )

    if return_code == 2:
        print("[PASS] Negative min-packets test passed")
        return True
    else:
        print(f"[FAIL] Negative min-packets should return exit code 2, got {return_code}")
        return False


def test_warn_exceeds_crit_drop():
    """Test that drop warning exceeding critical is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py',
         '--drop-warn', '10', '--drop-crit', '5']
    )

    if return_code == 2:
        print("[PASS] Drop warn > crit test passed")
        return True
    else:
        print(f"[FAIL] Drop warn > crit should return exit code 2, got {return_code}")
        return False


def test_warn_exceeds_crit_backlog():
    """Test that backlog warning exceeding critical is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py',
         '--backlog-warn', '10000', '--backlog-crit', '1000']
    )

    if return_code == 2:
        print("[PASS] Backlog warn > crit test passed")
        return True
    else:
        print(f"[FAIL] Backlog warn > crit should return exit code 2, got {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py',
         '--format', 'json', '--verbose', '--warn-only',
         '--drop-warn', '0.5', '--backlog-warn', '500']
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py']
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
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            required_keys = ['issues', 'summary', 'qdiscs']
            if all(k in data for k in required_keys):
                if 'critical' in data['issues'] and 'warning' in data['issues']:
                    print("[PASS] JSON structure test passed")
                    return True
        except json.JSONDecodeError:
            pass

    # Exit 2 is acceptable for tc unavailable
    if return_code == 2:
        print("[PASS] JSON structure test passed (tc unavailable)")
        return True

    print(f"[FAIL] JSON structure test failed")
    return False


def test_invalid_format():
    """Test that invalid format is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_network_qdisc_monitor.py', '--format', 'invalid']
    )

    if return_code != 0 and 'invalid choice' in stderr:
        print("[PASS] Invalid format test passed")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_network_qdisc_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_format_option_plain,
        test_format_option_json,
        test_format_option_table,
        test_verbose_flag,
        test_warn_only_flag,
        test_interface_option,
        test_multiple_interfaces,
        test_include_loopback_flag,
        test_drop_warn_option,
        test_drop_crit_option,
        test_backlog_warn_option,
        test_backlog_crit_option,
        test_min_packets_option,
        test_negative_drop_warn,
        test_drop_warn_exceeds_100,
        test_negative_backlog_warn,
        test_negative_min_packets,
        test_warn_exceeds_crit_drop,
        test_warn_exceeds_crit_backlog,
        test_combined_options,
        test_exit_code_validity,
        test_json_structure,
        test_invalid_format,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    sys.exit(0 if passed == total else 1)
