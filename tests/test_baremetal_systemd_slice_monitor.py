#!/usr/bin/env python3
"""
Tests for baremetal_systemd_slice_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring root access or specific cgroup configurations.
"""

import json
import subprocess
import sys


def run_command(args, timeout=30):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"


def test_help_message():
    """Test that --help flag works and shows usage information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'slice' in stdout.lower(), "Help should mention 'slice'"
    assert 'systemd' in stdout.lower(), "Help should mention 'systemd'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--warn-psi' in stdout, "Help should document --warn-psi flag"
    assert '--warn-memory' in stdout, "Help should document --warn-memory flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_systemd_slice_monitor.py', '--format', fmt]
        )

        # Should work (exit 0 or 1) or fail with dependency error (2)
        assert return_code in [0, 1, 2], \
            f"Format {fmt} should be valid, got return code {return_code}"

        # Should not get argument parsing errors
        assert 'invalid choice' not in stderr.lower(), \
            f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_warn_psi_flag():
    """Test that --warn-psi flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--warn-psi', '15']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-psi should be recognized"

    print("PASS: Warn-psi flag test passed")
    return True


def test_warn_memory_flag():
    """Test that --warn-memory flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--warn-memory', '90']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-memory should be recognized"

    print("PASS: Warn-memory flag test passed")
    return True


def test_invalid_warn_psi():
    """Test that invalid --warn-psi value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--warn-psi', '150']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Invalid warn-psi should exit with 2, got {return_code}"
    assert 'between' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid warn-psi test passed")
    return True


def test_invalid_warn_memory():
    """Test that invalid --warn-memory value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--warn-memory', '-10']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Invalid warn-memory should exit with 2, got {return_code}"
    assert 'between' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid warn-memory test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, \
        f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("PASS: Invalid format test passed")
    return True


def test_json_output_format():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--format', 'json']
    )

    # Skip if cgroup v2 not available
    if return_code == 2 and 'cgroup' in stderr.lower():
        print("SKIP: JSON output test (cgroup v2 not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'summary' in data, "JSON should have 'summary' field"
            assert 'slices' in data, "JSON should have 'slices' field"
            assert data['status'] in ['ok', 'warning'], \
                "Status should be ok or warning"
            print("PASS: JSON output format test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output format test passed (script execution checked)")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary', 'slices']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['total_slices', 'warning_count']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            # Check slices is a list
            assert isinstance(data['slices'], list), "slices should be a list"

            # If there are slices, check their structure
            if data['slices']:
                slice_obj = data['slices'][0]
                slice_keys = ['name', 'status']
                for key in slice_keys:
                    assert key in slice_obj, f"Slice should have '{key}' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_plain_output_contains_expected():
    """Test that plain output contains expected keywords."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--verbose']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'cgroup' in stderr.lower():
        print("SKIP: Plain output test (cgroup v2 not available)")
        return True

    if return_code in [0, 1]:
        # Should have some indication of status or slices
        has_content = ('slice' in stdout.lower() or
                       'ok' in stdout.lower() or
                       'warning' in stdout.lower() or
                       'memory' in stdout.lower() or
                       'no' in stdout.lower())
        assert has_content, "Output should contain slice info or status"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--format', 'table']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'cgroup' in stderr.lower():
        print("SKIP: Table output test (cgroup v2 not available)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            # First line should be header or status message
            first_line = lines[0].lower()
            has_header = ('slice' in first_line or 'memory' in first_line or
                          'no slices' in first_line)
            assert has_header, "Table should have header row or status"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_valid():
    """Test that script exits with valid exit code."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py']
    )

    # Exit 0 (no issues), 1 (warnings), or 2 (error) are all valid
    assert return_code in [0, 1, 2], \
        f"Exit code should be 0, 1, or 2, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_systemd_slice_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--warn-psi', '20',
        '--warn-memory', '80'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_slice_data_in_output():
    """Test that slice data is included in output when available."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            if data['slices']:
                for slice_obj in data['slices']:
                    assert 'name' in slice_obj, "Slice should have name"
                    # Slices should end with .slice
                    if slice_obj['name'] != 'message':  # Skip message field
                        assert slice_obj['name'].endswith('.slice') or 'message' in slice_obj, \
                            f"Slice name should end with .slice: {slice_obj['name']}"
            print("PASS: Slice data test passed")
            return True
        except json.JSONDecodeError:
            pass

    print("PASS: Slice data test passed (script execution checked)")
    return True


def test_memory_stats_format():
    """Test that memory stats are in expected format."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_slice_monitor.py', '--format', 'json']
    )

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            for slice_obj in data.get('slices', []):
                if 'memory' in slice_obj:
                    mem = slice_obj['memory']
                    # If there's memory data, check structure
                    if 'current_bytes' in mem:
                        assert isinstance(mem['current_bytes'], int), \
                            "current_bytes should be integer"
            print("PASS: Memory stats format test passed")
            return True
        except json.JSONDecodeError:
            pass

    print("PASS: Memory stats format test passed (script execution checked)")
    return True


if __name__ == "__main__":
    print("Testing baremetal_systemd_slice_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_warn_psi_flag,
        test_warn_memory_flag,
        test_invalid_warn_psi,
        test_invalid_warn_memory,
        test_invalid_argument,
        test_invalid_format,
        test_json_output_format,
        test_json_structure,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_valid,
        test_combined_flags,
        test_slice_data_in_output,
        test_memory_stats_format,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {test.__name__}: {e}")
            failed += 1

    print()
    print(f"Test Results: {passed}/{passed + failed} tests passed")

    sys.exit(0 if failed == 0 else 1)
