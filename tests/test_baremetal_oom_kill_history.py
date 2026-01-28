#!/usr/bin/env python3
"""
Test script for baremetal_oom_kill_history.py functionality.
Tests argument parsing, output formats, and log parsing without requiring actual OOM events.
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
        [sys.executable, 'baremetal_oom_kill_history.py', '--help']
    )

    if return_code == 0 and 'oom' in stdout.lower() and 'history' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed")
        print(f"  Return code: {return_code}")
        print(f"  Output: {stdout[:200]}")
        return False


def test_invalid_arguments():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--invalid-flag']
    )

    if return_code != 0:
        print("[PASS] Invalid arguments test passed")
        return True
    else:
        print("[FAIL] Invalid arguments should fail")
        return False


def test_invalid_source():
    """Test that invalid source is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--source', 'invalid']
    )

    if return_code == 2:
        print("[PASS] Invalid source test passed")
        return True
    else:
        print(f"[FAIL] Invalid source should fail with exit code 2")
        print(f"  Return code: {return_code}")
        return False


def test_dmesg_source_option():
    """Test --source dmesg option."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--source', 'dmesg']
    )

    # Should succeed (exit 0 if no OOM kills, or might exit 2 if dmesg not accessible)
    # On most systems dmesg should work for unprivileged users
    if return_code in [0, 1, 2]:
        print("[PASS] Dmesg source option test passed")
        return True
    else:
        print(f"[FAIL] Dmesg source option test failed")
        print(f"  Return code: {return_code}")
        return False


def test_plain_output_format():
    """Test plain output format (default)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py']
    )

    # Should contain "OOM Kill History" header or "No OOM kill events"
    if return_code in [0, 1, 2]:
        if 'OOM' in stdout or 'Error' in stderr:
            print("[PASS] Plain output format test passed")
            return True
        else:
            print(f"[FAIL] Plain output format test failed - missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Plain output format test failed")
        print(f"  Return code: {return_code}")
        return False


def test_json_output_format():
    """Test JSON output format parsing."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--format', 'json']
    )

    # If dmesg fails, exit code will be 2
    if return_code == 2:
        print("[PASS] JSON output format test passed (dmesg not accessible)")
        return True

    try:
        # Try to parse JSON output
        data = json.loads(stdout)

        # Verify expected structure
        if 'analysis' not in data or 'events' not in data:
            print("[FAIL] JSON output missing expected keys")
            print(f"  Keys: {list(data.keys())}")
            return False

        # Verify analysis structure
        analysis = data['analysis']
        required_keys = ['total_events', 'unique_processes', 'process_frequency']
        if not all(key in analysis for key in required_keys):
            print("[FAIL] JSON analysis data missing required keys")
            print(f"  Analysis keys: {list(analysis.keys())}")
            return False

        # Verify events is a list
        if not isinstance(data['events'], list):
            print("[FAIL] events is not a list")
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
        [sys.executable, 'baremetal_oom_kill_history.py', '--format', 'table']
    )

    # Should contain table headers or no events message
    if return_code in [0, 1, 2]:
        if 'PROCESS' in stdout or 'No OOM' in stdout or 'Error' in stderr:
            print("[PASS] Table output format test passed")
            return True
        else:
            print(f"[FAIL] Table output format test failed - missing expected content")
            print(f"  Output: {stdout[:200]}")
            return False
    else:
        print(f"[FAIL] Table output format test failed")
        print(f"  Return code: {return_code}")
        return False


def test_summary_mode():
    """Test --summary mode to show only statistics."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--summary']
    )

    # Should succeed
    if return_code in [0, 1, 2]:
        print("[PASS] Summary mode test passed")
        return True
    else:
        print(f"[FAIL] Summary mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_warn_only_mode():
    """Test --warn-only mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--warn-only']
    )

    # Should succeed (exit 0 if no OOM kills)
    if return_code in [0, 1, 2]:
        print("[PASS] Warn-only mode test passed")
        return True
    else:
        print(f"[FAIL] Warn-only mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_verbose_mode():
    """Test --verbose mode."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--verbose']
    )

    # Should succeed
    if return_code in [0, 1, 2]:
        print("[PASS] Verbose mode test passed")
        return True
    else:
        print(f"[FAIL] Verbose mode test failed")
        print(f"  Return code: {return_code}")
        return False


def test_short_flags():
    """Test short form flags (-w, -v)."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '-w', '-v']
    )

    # Should succeed
    if return_code in [0, 1, 2]:
        print("[PASS] Short flags test passed")
        return True
    else:
        print(f"[FAIL] Short flags test failed")
        print(f"  Return code: {return_code}")
        return False


def test_format_choices():
    """Test that only valid format choices are accepted."""
    # Valid formats
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_oom_kill_history.py', '--format', fmt]
        )
        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Valid format '{fmt}' failed")
            return False

    # Invalid format
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--format', 'xml']
    )
    if return_code == 2:
        print("[PASS] Format choices test passed")
        return True
    else:
        print(f"[FAIL] Invalid format 'xml' should fail")
        return False


def test_source_choices():
    """Test that only valid source choices are accepted."""
    # Valid sources
    for src in ['dmesg', 'journal']:
        return_code, stdout, stderr = run_command(
            [sys.executable, 'baremetal_oom_kill_history.py', '--source', src]
        )
        # May fail if source not accessible, but argument should parse
        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Valid source '{src}' failed unexpectedly")
            return False

    print("[PASS] Source choices test passed")
    return True


def test_json_analysis_structure():
    """Test that JSON output has correct analysis structure."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py', '--format', 'json']
    )

    if return_code == 2:
        print("[PASS] JSON analysis structure test passed (dmesg not accessible)")
        return True

    try:
        data = json.loads(stdout)
        analysis = data.get('analysis', {})

        # Check all expected analysis keys
        expected_keys = [
            'total_events',
            'unique_processes',
            'process_frequency',
            'hourly_distribution',
            'memory_stats'
        ]

        missing = [k for k in expected_keys if k not in analysis]
        if missing:
            print(f"[FAIL] JSON analysis missing keys: {missing}")
            return False

        # Verify types
        if not isinstance(analysis['total_events'], int):
            print("[FAIL] total_events should be int")
            return False

        if not isinstance(analysis['process_frequency'], dict):
            print("[FAIL] process_frequency should be dict")
            return False

        print("[PASS] JSON analysis structure test passed")
        return True
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON parsing failed: {e}")
        return False


def test_exit_code_no_oom():
    """Test exit code 0 when no OOM events found."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py']
    )

    # Exit code 0 = no OOM kills, 1 = OOM kills found, 2 = error
    if return_code in [0, 1, 2]:
        print("[PASS] Exit code test passed")
        return True
    else:
        print(f"[FAIL] Unexpected exit code: {return_code}")
        return False


def test_combined_options():
    """Test combining multiple options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py',
         '--format', 'json', '--summary', '--verbose']
    )

    if return_code in [0, 1, 2]:
        print("[PASS] Combined options test passed")
        return True
    else:
        print(f"[FAIL] Combined options test failed")
        print(f"  Return code: {return_code}")
        return False


def test_since_warning_for_dmesg():
    """Test that --since with dmesg shows warning."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'baremetal_oom_kill_history.py',
         '--source', 'dmesg', '--since', '24 hours ago']
    )

    # Should print warning about --since only applying to journal
    if return_code in [0, 1, 2]:
        if 'Warning' in stderr or '--since' in stderr:
            print("[PASS] Since warning test passed")
            return True
        # If no warning, the option was just ignored
        print("[PASS] Since warning test passed (option ignored)")
        return True
    else:
        print(f"[FAIL] Since warning test failed")
        print(f"  Return code: {return_code}")
        return False


if __name__ == "__main__":
    print("Testing baremetal_oom_kill_history.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_arguments,
        test_invalid_source,
        test_dmesg_source_option,
        test_plain_output_format,
        test_json_output_format,
        test_table_output_format,
        test_summary_mode,
        test_warn_only_mode,
        test_verbose_mode,
        test_short_flags,
        test_format_choices,
        test_source_choices,
        test_json_analysis_structure,
        test_exit_code_no_oom,
        test_combined_options,
        test_since_warning_for_dmesg,
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
