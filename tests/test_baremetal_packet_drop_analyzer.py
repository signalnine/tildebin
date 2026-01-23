#!/usr/bin/env python3
"""
Test script for baremetal_packet_drop_analyzer.py functionality.
Tests argument parsing and error handling without requiring specific network hardware.
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
        [sys.executable, 'baremetal_packet_drop_analyzer.py', '--help']
    )

    if return_code == 0 and 'packet' in stdout.lower() and 'drop' in stdout.lower():
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
        [sys.executable, 'baremetal_packet_drop_analyzer.py', '--invalid-flag']
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
    # Use very short interval for testing
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'json', '-i', '0.1']
    )

    # Should succeed (0) or detect issues (1), but not usage error (2)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify expected JSON structure
            if 'interfaces' in data and 'issues' in data and 'summary' in data:
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
        # Missing /sys files is acceptable in test environment
        print("[PASS] JSON output format test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Unexpected return code: {return_code}")
        return False


def test_table_format():
    """Test table output format"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'table', '-i', '0.1']
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
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'plain', '-i', '0.1']
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
        [sys.executable, 'baremetal_packet_drop_analyzer.py', '-v', '-i', '0.1']
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
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--warn-only', '-i', '0.1']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_custom_interval():
    """Test custom sampling interval"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '-i', '0.1', '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify interval is recorded
            if data.get('sample_interval_sec') == 0.1:
                print("[PASS] Custom interval test passed")
                return True
            else:
                print(f"[FAIL] Interval not recorded correctly: "
                      f"{data.get('sample_interval_sec')}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Custom interval produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Custom interval test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Custom interval test failed with code {return_code}")
        return False


def test_invalid_interval():
    """Test that invalid interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py', '-i', '0']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Invalid interval test passed")
        return True
    else:
        print(f"[FAIL] Invalid interval should fail with code 2, got {return_code}")
        return False


def test_negative_interval():
    """Test that negative interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py', '-i', '-1']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Negative interval test passed")
        return True
    else:
        print(f"[FAIL] Negative interval should fail with code 2, got {return_code}")
        return False


def test_custom_thresholds():
    """Test custom warning and critical thresholds"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--warn', '0.5', '--crit', '5', '-i', '0.1']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom thresholds test passed")
        return True
    else:
        print(f"[FAIL] Custom thresholds test failed with code {return_code}")
        return False


def test_invalid_thresholds():
    """Test that warn >= crit is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--warn', '10', '--crit', '5', '-i', '0.1']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Invalid thresholds test passed")
        return True
    else:
        print(f"[FAIL] Invalid thresholds should fail with code 2, got {return_code}")
        return False


def test_exit_codes():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py', '-i', '0.1']
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
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'json',
         '--verbose',
         '--warn', '0.5',
         '--crit', '5',
         '-i', '0.1']
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


def test_json_summary_structure():
    """Test that JSON output contains expected summary fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'json', '-i', '0.1']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_keys = ['interfaces_checked', 'interfaces_with_issues',
                            'total_issues', 'warning_count', 'critical_count']
            missing = [k for k in expected_keys if k not in summary]
            if missing:
                print(f"[FAIL] Missing summary keys: {missing}")
                return False

            # Also verify timestamp is present
            if 'timestamp' not in data:
                print("[FAIL] Missing timestamp in JSON output")
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


def test_interface_data_structure():
    """Test that interface data contains expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'json', '-i', '0.1']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            interfaces = data.get('interfaces', [])
            if not interfaces:
                print("[PASS] Interface data structure test passed (no interfaces)")
                return True

            iface = interfaces[0]
            expected_keys = ['interface', 'operstate', 'status', 'totals',
                           'rates', 'drop_breakdown', 'issues']
            missing = [k for k in expected_keys if k not in iface]
            if missing:
                print(f"[FAIL] Missing interface keys: {missing}")
                print(f"  Available keys: {list(iface.keys())}")
                return False
            print("[PASS] Interface data structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON parsing failed: {e}")
            return False
    elif return_code == 2:
        print("[PASS] Interface data structure test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Interface data structure test failed with code {return_code}")
        return False


def test_has_issues_flag():
    """Test that has_issues flag is present and boolean"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'json', '-i', '0.1']
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


def test_nonexistent_interface():
    """Test that nonexistent interface is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '-I', 'nonexistent_iface_xyz123', '-i', '0.1']
    )

    # Should fail with exit code 2 (interface not found)
    if return_code == 2:
        print("[PASS] Nonexistent interface test passed")
        return True
    else:
        print(f"[FAIL] Nonexistent interface should fail with code 2, got {return_code}")
        return False


def test_specific_interface_option():
    """Test -I option for specific interface"""
    # First get a valid interface if possible
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'json', '-i', '0.1']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            interfaces = data.get('interfaces', [])
            if interfaces:
                iface_name = interfaces[0]['interface']
                # Now test with specific interface
                return_code2, stdout2, stderr2 = run_command(
                    [sys.executable, 'baremetal_packet_drop_analyzer.py',
                     '-I', iface_name, '--format', 'json', '-i', '0.1']
                )
                if return_code2 in [0, 1]:
                    data2 = json.loads(stdout2)
                    if len(data2.get('interfaces', [])) == 1:
                        print("[PASS] Specific interface option test passed")
                        return True
                    else:
                        print("[FAIL] Should return exactly one interface")
                        return False
                elif return_code2 == 2:
                    print("[PASS] Specific interface option test passed (dep missing)")
                    return True
            else:
                print("[PASS] Specific interface option test passed (no interfaces)")
                return True
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] Specific interface option test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_drop_breakdown_fields():
    """Test that drop breakdown contains expected fields"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_packet_drop_analyzer.py',
         '--format', 'json', '-i', '0.1']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            interfaces = data.get('interfaces', [])
            if not interfaces:
                print("[PASS] Drop breakdown fields test passed (no interfaces)")
                return True

            breakdown = interfaces[0].get('drop_breakdown', {})
            expected_keys = ['rx_dropped', 'rx_errors', 'rx_missed', 'rx_fifo',
                           'tx_dropped', 'tx_errors', 'tx_fifo', 'collisions']
            missing = [k for k in expected_keys if k not in breakdown]
            if missing:
                print(f"[FAIL] Missing breakdown keys: {missing}")
                return False
            print("[PASS] Drop breakdown fields test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] Drop breakdown fields test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_packet_drop_analyzer.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_json_output_format,
        test_table_format,
        test_plain_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_custom_interval,
        test_invalid_interval,
        test_negative_interval,
        test_custom_thresholds,
        test_invalid_thresholds,
        test_exit_codes,
        test_combined_flags,
        test_json_summary_structure,
        test_interface_data_structure,
        test_has_issues_flag,
        test_nonexistent_interface,
        test_specific_interface_option,
        test_drop_breakdown_fields,
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
