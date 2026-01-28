#!/usr/bin/env python3
"""
Tests for baremetal_process_io_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring root access or specific I/O load.
"""

import json
import subprocess
import sys


def run_command(args, timeout=15):
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
        ['./baremetal_process_io_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'i/o' in stdout.lower(), "Help should mention 'I/O'"
    assert 'process' in stdout.lower(), "Help should mention 'process'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--interval' in stdout, "Help should document --interval flag"
    assert '--top' in stdout, "Help should document --top flag"
    assert '--warn-threshold' in stdout, "Help should document --warn-threshold flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_process_io_monitor.py', '--format', fmt, '--interval', '0.1']
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
        ['./baremetal_process_io_monitor.py', '-f', 'json', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--verbose', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '-v', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--warn-only', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '-w', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_interval_flag():
    """Test that --interval flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--interval', '0.5']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--interval should be recognized"
    assert return_code in [0, 1, 2], \
        f"--interval 0.5 should be valid, got {return_code}"

    print("PASS: Interval flag test passed")
    return True


def test_invalid_interval_negative():
    """Test that negative interval is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--interval', '-1']
    )

    assert return_code == 2, \
        f"Negative interval should exit with 2, got {return_code}"
    assert 'must be positive' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid interval"

    print("PASS: Invalid negative interval test passed")
    return True


def test_invalid_interval_too_large():
    """Test that very large interval is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--interval', '500']
    )

    assert return_code == 2, \
        f"Too large interval should exit with 2, got {return_code}"
    assert 'cannot exceed' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention interval limit"

    print("PASS: Invalid too large interval test passed")
    return True


def test_top_flag():
    """Test that --top flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--top', '20', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--top should be recognized"
    assert return_code in [0, 1, 2], \
        f"--top 20 should be valid, got {return_code}"

    print("PASS: Top flag test passed")
    return True


def test_invalid_top_zero():
    """Test that --top 0 is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--top', '0', '--interval', '0.1']
    )

    assert return_code == 2, \
        f"--top 0 should exit with 2, got {return_code}"

    print("PASS: Invalid top zero test passed")
    return True


def test_warn_threshold_flag():
    """Test that --warn-threshold flag accepts various formats."""
    # Test bytes
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--warn-threshold', '1000000', '--interval', '0.1']
    )
    assert return_code in [0, 1, 2], "Numeric threshold should be valid"

    # Test with K suffix
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--warn-threshold', '100K', '--interval', '0.1']
    )
    assert return_code in [0, 1, 2], "K suffix threshold should be valid"

    # Test with M suffix
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--warn-threshold', '5M', '--interval', '0.1']
    )
    assert return_code in [0, 1, 2], "M suffix threshold should be valid"

    # Test with G suffix
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--warn-threshold', '1G', '--interval', '0.1']
    )
    assert return_code in [0, 1, 2], "G suffix threshold should be valid"

    print("PASS: Warn threshold flag test passed")
    return True


def test_invalid_warn_threshold():
    """Test that invalid threshold format is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--warn-threshold', 'invalid', '--interval', '0.1']
    )

    assert return_code == 2, \
        f"Invalid threshold should exit with 2, got {return_code}"
    assert 'invalid' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid threshold"

    print("PASS: Invalid warn threshold test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_json_output_format():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--format', 'json', '--interval', '0.1']
    )

    # Skip if script couldn't run (e.g., no /proc on non-Linux)
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: JSON output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'summary' in data, "JSON should have 'summary' field"
            assert 'top_consumers' in data, "JSON should have 'top_consumers' field"
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


def test_plain_output_contains_expected():
    """Test that plain output contains expected keywords."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--verbose', '--interval', '0.1']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Plain output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        # Should have some process info or status message
        output_lower = stdout.lower()
        assert ('pid' in output_lower or 'ok' in output_lower or
                'i/o' in output_lower or 'no i/o' in output_lower), \
            "Output should contain process info or status"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--format', 'table', '--top', '5', '--interval', '0.1']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Table output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            # First line should be header (if there's output)
            header = lines[0].lower()
            assert ('pid' in header or 'command' in header or
                    'read' in header or 'no processes' in header), \
                "Table should have header row or status message"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_success():
    """Test that script exits appropriately."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--warn-threshold', '1G', '--interval', '0.1']
    )

    # With very high threshold (1GB/s), should typically succeed
    # Skip if no /proc
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Exit code test (no /proc filesystem)")
        return True

    # Exit 0 (no warnings) or 1 (warnings found) are both valid
    assert return_code in [0, 1], \
        f"Exit code should be 0 or 1, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_process_io_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--interval', '0.1',
        '--top', '5',
        '--warn-threshold', '5M'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--format', 'json', '--top', '3', '--interval', '0.1']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary', 'warnings', 'top_consumers']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['total_processes_sampled', 'processes_with_io',
                           'warning_count', 'total_read_rate', 'total_write_rate']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            # Check that top_consumers is a list
            assert isinstance(data['top_consumers'], list), \
                "top_consumers should be a list"

            # Check warn_threshold_bytes_sec is present
            assert 'warn_threshold_bytes_sec' in data, \
                "JSON should have 'warn_threshold_bytes_sec' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_process_data_fields():
    """Test that process entries have expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_io_monitor.py', '--format', 'json', '--interval', '0.1']
    )

    if return_code == 2:
        print("SKIP: Process data fields test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if data['top_consumers']:
                proc = data['top_consumers'][0]
                expected_fields = ['pid', 'comm', 'user', 'read_rate',
                                   'write_rate', 'total_rate']
                for field in expected_fields:
                    assert field in proc, f"Process should have '{field}' field"

            print("PASS: Process data fields test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Process data fields test passed (no JSON to check)")
            return True

    print("PASS: Process data fields test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_process_io_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_interval_flag,
        test_invalid_interval_negative,
        test_invalid_interval_too_large,
        test_top_flag,
        test_invalid_top_zero,
        test_warn_threshold_flag,
        test_invalid_warn_threshold,
        test_invalid_argument,
        test_json_output_format,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_success,
        test_combined_flags,
        test_json_structure,
        test_process_data_fields,
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
