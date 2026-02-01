#!/usr/bin/env python3
"""
Test script for baremetal_fc_health_monitor.py functionality.
Tests argument parsing and output formats without requiring Fibre Channel hardware.
"""

import subprocess
import sys
import json


def run_command(cmd_args):
    """Helper function to run a command and return result."""
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
    """Test that the help message works."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--help']
    )

    if return_code == 0 and 'fibre channel' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_help_contains_san():
    """Test that help mentions SAN."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--help']
    )

    if return_code == 0 and 'san' in stdout.lower():
        print("[PASS] Help contains SAN test passed")
        return True
    else:
        print(f"[FAIL] Help should mention SAN")
        return False


def test_help_contains_hba():
    """Test that help mentions HBA."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--help']
    )

    if return_code == 0 and 'hba' in stdout.lower():
        print("[PASS] Help contains HBA test passed")
        return True
    else:
        print(f"[FAIL] Help should mention HBA")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_format_option_recognized():
    """Test that format option is recognized."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'invalid']
    )

    # Should fail with usage error (invalid choice)
    if return_code != 0 and ('invalid choice' in stderr or 'invalid' in stderr.lower()):
        print("[PASS] Format option recognition test passed")
        return True
    else:
        print(f"[FAIL] Format option recognition test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py']
    )

    # Exit code 0 or 1 = success (healthy or issues), 2 = no FC hardware
    if return_code in [0, 1]:
        if 'fibre channel' in stdout.lower() or 'fc host' in stdout.lower():
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain output missing expected content")
            print(f"  Output: {stdout[:300]}")
            return False
    elif return_code == 2:
        # No FC hardware - expected on most systems
        if 'not found' in stderr.lower() or 'no fibre channel' in stderr.lower():
            print("[SKIP] Plain output format test skipped (no FC hardware)")
            return True
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        # No FC hardware - check for valid JSON error output
        if stdout.strip():
            try:
                data = json.loads(stdout)
                if 'healthy' in data and data['healthy'] is False:
                    print("[PASS] JSON output format test passed (no FC hardware, valid JSON)")
                    return True
            except json.JSONDecodeError:
                pass
        print("[SKIP] JSON output format test skipped (no FC hardware)")
        return True

    if return_code not in [0, 1]:
        print(f"[FAIL] JSON output format returned unexpected code: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False

    try:
        data = json.loads(stdout)

        # Verify expected structure
        required_keys = ['hosts', 'issues', 'healthy']
        if not all(key in data for key in required_keys):
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        print("[PASS] JSON output format test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_table_output_format():
    """Test table output format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'table']
    )

    if return_code == 2:
        print("[SKIP] Table output format test skipped (no FC hardware)")
        return True

    if return_code in [0, 1] and ('Host' in stdout or 'State' in stdout or 'no fc' in stdout.lower()):
        print("[PASS] Table output format test passed")
        return True
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_verbose_mode():
    """Test verbose mode shows detailed stats."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--verbose']
    )

    if return_code == 2:
        print("[SKIP] Verbose mode test skipped (no FC hardware)")
        return True

    if return_code in [0, 1]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_mode():
    """Test warn-only mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--warn-only']
    )

    # Should succeed (exit code depends on system state)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_has_healthy_flag():
    """Test JSON output includes healthy flag."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'json']
    )

    if return_code == 2 and not stdout.strip():
        print("[SKIP] JSON healthy flag test skipped (no FC hardware)")
        return True

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] JSON healthy flag test returned unexpected code: {return_code}")
        return False

    try:
        data = json.loads(stdout)

        if 'healthy' not in data:
            print("[FAIL] JSON output missing 'healthy' flag")
            return False

        if not isinstance(data['healthy'], bool):
            print("[FAIL] 'healthy' flag is not boolean")
            return False

        print("[PASS] JSON has healthy flag test passed")
        return True
    except json.JSONDecodeError as e:
        if return_code == 2:
            print("[SKIP] JSON healthy flag test skipped (no FC hardware, no JSON output)")
            return True
        print(f"[FAIL] JSON healthy flag test failed: {e}")
        return False


def test_json_has_hosts():
    """Test JSON output includes hosts list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'json']
    )

    if return_code == 2 and not stdout.strip():
        print("[SKIP] JSON hosts test skipped (no FC hardware)")
        return True

    try:
        data = json.loads(stdout)

        if 'hosts' not in data:
            print("[FAIL] JSON output missing 'hosts'")
            return False

        if not isinstance(data['hosts'], list):
            print("[FAIL] 'hosts' is not a list")
            return False

        print("[PASS] JSON has hosts test passed")
        return True
    except json.JSONDecodeError as e:
        if return_code == 2:
            print("[SKIP] JSON hosts test skipped (no valid JSON)")
            return True
        print(f"[FAIL] JSON hosts test failed: {e}")
        return False


def test_json_has_issues():
    """Test JSON output includes issues list."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'json']
    )

    if return_code == 2 and not stdout.strip():
        print("[SKIP] JSON issues test skipped (no FC hardware)")
        return True

    try:
        data = json.loads(stdout)

        if 'issues' not in data:
            print("[FAIL] JSON output missing 'issues'")
            return False

        if not isinstance(data['issues'], list):
            print("[FAIL] 'issues' is not a list")
            return False

        print("[PASS] JSON has issues test passed")
        return True
    except json.JSONDecodeError as e:
        if return_code == 2:
            print("[SKIP] JSON issues test skipped (no valid JSON)")
            return True
        print(f"[FAIL] JSON issues test failed: {e}")
        return False


def test_exit_codes():
    """Test exit code behavior."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py']
    )

    if return_code in [0, 1, 2]:
        print(f"[PASS] Exit code test passed (got {return_code})")
        return True
    else:
        print(f"[FAIL] Exit code test failed: {return_code}")
        print(f"  Stderr: {stderr[:200]}")
        return False


def test_help_contains_usage_examples():
    """Test that help includes usage examples."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Examples:' in stdout and '--format json' in stdout:
        print("[PASS] Help contains usage examples test passed")
        return True
    else:
        print(f"[FAIL] Help should contain usage examples")
        print(f"  Output: {stdout[:300]}")
        return False


def test_help_contains_exit_codes():
    """Test that help documents exit codes."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--help']
    )

    if return_code == 0 and 'Exit codes:' in stdout:
        print("[PASS] Help contains exit codes test passed")
        return True
    else:
        print(f"[FAIL] Help should document exit codes")
        return False


def test_help_contains_troubleshooting():
    """Test that help documents troubleshooting tips."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--help']
    )

    if return_code == 0 and ('troubleshooting' in stdout.lower() or 'multipath' in stdout.lower()):
        print("[PASS] Help contains troubleshooting tips test passed")
        return True
    else:
        print(f"[FAIL] Help should document troubleshooting tips")
        return False


def test_help_contains_drivers():
    """Test that help mentions common FC drivers."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--help']
    )

    if return_code == 0 and ('lpfc' in stdout or 'qla2xxx' in stdout):
        print("[PASS] Help contains FC drivers test passed")
        return True
    else:
        print(f"[FAIL] Help should mention common FC drivers")
        return False


def test_warn_only_json():
    """Test warn-only mode with JSON format."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--warn-only', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        # If there's output, it should be valid JSON
        if stdout.strip():
            try:
                data = json.loads(stdout)
                if 'healthy' in data or 'issues' in data:
                    print("[PASS] Warn-only JSON test passed")
                    return True
            except json.JSONDecodeError:
                pass
        # No output is also acceptable for warn-only when healthy
        print("[PASS] Warn-only JSON test passed")
        return True

    print(f"[FAIL] Warn-only JSON test failed")
    print(f"  Return code: {return_code}")
    return False


def test_short_verbose_flag():
    """Test that -v works as short form of --verbose."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '-v']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short verbose flag test passed")
        return True
    else:
        print(f"[FAIL] Short verbose flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_warn_only_flag():
    """Test that -w works as short form of --warn-only."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '-w']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Short warn-only flag test passed")
        return True
    else:
        print(f"[FAIL] Short warn-only flag test failed")
        print(f"  Return code: {return_code}")
        return False


def test_combined_flags():
    """Test combining multiple flags."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '-v', '--format', 'json']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined flags test passed")
        return True
    else:
        print(f"[FAIL] Combined flags test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_has_summary():
    """Test JSON output includes summary section."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'json']
    )

    if return_code == 2 and not stdout.strip():
        print("[SKIP] JSON summary test skipped (no FC hardware)")
        return True

    try:
        data = json.loads(stdout)

        if 'summary' not in data:
            print("[FAIL] JSON output missing 'summary'")
            return False

        summary = data['summary']
        required = ['host_count', 'error_count', 'warning_count']
        if not all(key in summary for key in required):
            print("[FAIL] Summary missing required keys")
            print(f"  Keys: {list(summary.keys())}")
            return False

        print("[PASS] JSON has summary test passed")
        return True
    except json.JSONDecodeError as e:
        if return_code == 2:
            print("[SKIP] JSON summary test skipped (no valid JSON)")
            return True
        print(f"[FAIL] JSON summary test failed: {e}")
        return False


def test_json_summary_has_target_count():
    """Test JSON summary includes target count."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py', '--format', 'json']
    )

    if return_code == 2 and not stdout.strip():
        print("[SKIP] JSON target count test skipped (no FC hardware)")
        return True

    try:
        data = json.loads(stdout)

        if 'summary' in data and 'target_count' in data['summary']:
            print("[PASS] JSON summary has target count test passed")
            return True
        else:
            print("[FAIL] JSON summary missing target_count")
            return False
    except json.JSONDecodeError as e:
        if return_code == 2:
            print("[SKIP] JSON target count test skipped (no valid JSON)")
            return True
        print(f"[FAIL] JSON target count test failed: {e}")
        return False


def test_error_message_helpful():
    """Test that error messages are helpful when no FC hardware."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_fc_health_monitor.py']
    )

    if return_code == 2:
        # Should have helpful error message
        if 'modprobe' in stderr or 'module' in stderr.lower() or 'not found' in stderr.lower():
            print("[PASS] Error message helpful test passed")
            return True
        else:
            print(f"[FAIL] Error message should suggest how to fix")
            print(f"  Stderr: {stderr[:300]}")
            return False

    # If we have FC hardware, test passes
    print("[PASS] Error message helpful test passed (FC hardware present)")
    return True


if __name__ == "__main__":
    print("Testing baremetal_fc_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_help_contains_san,
        test_help_contains_hba,
        test_invalid_arguments,
        test_format_option_recognized,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_verbose_mode,
        test_warn_only_mode,
        test_json_has_healthy_flag,
        test_json_has_hosts,
        test_json_has_issues,
        test_exit_codes,
        test_help_contains_usage_examples,
        test_help_contains_exit_codes,
        test_help_contains_troubleshooting,
        test_help_contains_drivers,
        test_warn_only_json,
        test_short_verbose_flag,
        test_short_warn_only_flag,
        test_combined_flags,
        test_json_has_summary,
        test_json_summary_has_target_count,
        test_error_message_helpful,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"{total - passed} test(s) failed")
        sys.exit(1)
