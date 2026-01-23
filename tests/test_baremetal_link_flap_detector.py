#!/usr/bin/env python3
"""
Test script for baremetal_link_flap_detector.py functionality.
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
        [sys.executable, 'baremetal_link_flap_detector.py', '--help']
    )

    if return_code == 0 and 'flap' in stdout.lower() and 'link' in stdout.lower():
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
        [sys.executable, 'baremetal_link_flap_detector.py', '--invalid-flag']
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
    # Use very short duration for testing
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json', '-d', '0.5']
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
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'table', '-d', '0.5']
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
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'plain', '-d', '0.5']
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
        [sys.executable, 'baremetal_link_flap_detector.py', '-v', '-d', '0.5']
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
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--warn-only', '-d', '0.5']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Warn-only flag test failed with code {return_code}")
        return False


def test_custom_duration():
    """Test custom monitoring duration"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '-d', '0.5', '--format', 'json']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Verify duration is recorded
            if data.get('monitoring_duration_sec') == 0.5:
                print("[PASS] Custom duration test passed")
                return True
            else:
                print(f"[FAIL] Duration not recorded correctly: "
                      f"{data.get('monitoring_duration_sec')}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] Custom duration produced invalid JSON")
            return False
    elif return_code == 2:
        print("[PASS] Custom duration test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Custom duration test failed with code {return_code}")
        return False


def test_invalid_duration():
    """Test that invalid duration is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py', '-d', '0']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Invalid duration test passed")
        return True
    else:
        print(f"[FAIL] Invalid duration should fail with code 2, got {return_code}")
        return False


def test_negative_duration():
    """Test that negative duration is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py', '-d', '-1']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Negative duration test passed")
        return True
    else:
        print(f"[FAIL] Negative duration should fail with code 2, got {return_code}")
        return False


def test_custom_threshold():
    """Test custom flapping threshold"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '-t', '5', '-d', '0.5']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Custom threshold test passed")
        return True
    else:
        print(f"[FAIL] Custom threshold test failed with code {return_code}")
        return False


def test_invalid_threshold():
    """Test that invalid threshold (0 or negative) is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '-t', '0', '-d', '0.5']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Invalid threshold test passed")
        return True
    else:
        print(f"[FAIL] Invalid threshold should fail with code 2, got {return_code}")
        return False


def test_poll_interval():
    """Test custom poll interval"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '-p', '0.2', '-d', '0.5']
    )

    # Should succeed (0), detect issues (1), or missing deps (2)
    if return_code in [0, 1, 2]:
        print("[PASS] Poll interval test passed")
        return True
    else:
        print(f"[FAIL] Poll interval test failed with code {return_code}")
        return False


def test_invalid_poll_interval():
    """Test that invalid poll interval is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '-p', '0', '-d', '0.5']
    )

    # Should fail with exit code 2 (usage error)
    if return_code == 2:
        print("[PASS] Invalid poll interval test passed")
        return True
    else:
        print(f"[FAIL] Invalid poll interval should fail with code 2, got {return_code}")
        return False


def test_exit_codes():
    """Test that exit codes are in valid range"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py', '-d', '0.5']
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
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json',
         '--verbose',
         '-t', '5',
         '-d', '0.5']
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
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json', '-d', '0.5']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            summary = data.get('summary', {})
            expected_keys = ['interfaces_checked', 'interfaces_flapping', 'total_issues']
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
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json', '-d', '0.5']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            interfaces = data.get('interfaces', [])
            if not interfaces:
                print("[PASS] Interface data structure test passed (no interfaces)")
                return True

            iface = interfaces[0]
            expected_keys = ['interface', 'operstate', 'carrier', 'monitoring_method',
                           'carrier_changes_during_window', 'flapping', 'transitions']
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


def test_has_flapping_flag():
    """Test that has_flapping flag is present and boolean"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json', '-d', '0.5']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            has_flapping = data.get('has_flapping')
            if isinstance(has_flapping, bool):
                print("[PASS] has_flapping flag test passed")
                return True
            else:
                print(f"[FAIL] has_flapping is not boolean: {has_flapping}")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] has_flapping flag test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_nonexistent_interface():
    """Test that nonexistent interface is rejected"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '-I', 'nonexistent_iface_xyz123', '-d', '0.5']
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
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json', '-d', '0.5']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            interfaces = data.get('interfaces', [])
            if interfaces:
                iface_name = interfaces[0]['interface']
                # Now test with specific interface
                return_code2, stdout2, stderr2 = run_command(
                    [sys.executable, 'baremetal_link_flap_detector.py',
                     '-I', iface_name, '--format', 'json', '-d', '0.5']
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


def test_monitoring_duration_recorded():
    """Test that monitoring duration is recorded in output"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json', '-d', '0.5']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if 'monitoring_duration_sec' in data:
                print("[PASS] Monitoring duration recorded test passed")
                return True
            else:
                print("[FAIL] Missing monitoring_duration_sec")
                return False
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] Monitoring duration recorded test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


def test_flapping_boolean_per_interface():
    """Test that each interface has a flapping boolean"""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_link_flap_detector.py',
         '--format', 'json', '-d', '0.5']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            interfaces = data.get('interfaces', [])
            for iface in interfaces:
                if 'flapping' not in iface:
                    print(f"[FAIL] Interface missing 'flapping' field: {iface.get('interface')}")
                    return False
                if not isinstance(iface['flapping'], bool):
                    print(f"[FAIL] 'flapping' is not boolean for {iface.get('interface')}")
                    return False
            print("[PASS] Flapping boolean per interface test passed")
            return True
        except json.JSONDecodeError:
            print("[FAIL] JSON parsing failed")
            return False
    elif return_code == 2:
        print("[PASS] Flapping boolean per interface test passed (dependency missing)")
        return True
    else:
        print(f"[FAIL] Test failed with code {return_code}")
        return False


if __name__ == "__main__":
    print(f"Testing baremetal_link_flap_detector.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_json_output_format,
        test_table_format,
        test_plain_format,
        test_verbose_flag,
        test_warn_only_flag,
        test_custom_duration,
        test_invalid_duration,
        test_negative_duration,
        test_custom_threshold,
        test_invalid_threshold,
        test_poll_interval,
        test_invalid_poll_interval,
        test_exit_codes,
        test_combined_flags,
        test_json_summary_structure,
        test_interface_data_structure,
        test_has_flapping_flag,
        test_nonexistent_interface,
        test_specific_interface_option,
        test_monitoring_duration_recorded,
        test_flapping_boolean_per_interface,
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
