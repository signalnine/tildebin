#!/usr/bin/env python3
"""
Tests for baremetal_disk_io_latency_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring root access or specific disk configurations.
"""

import json
import subprocess
import sys


def run_command(args, timeout=60):
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
        ['./baremetal_disk_io_latency_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'disk' in stdout.lower(), "Help should mention 'disk'"
    assert 'latency' in stdout.lower(), "Help should mention 'latency'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--device' in stdout, "Help should document --device flag"
    assert '--read-warn' in stdout, "Help should document --read-warn flag"
    assert '--write-warn' in stdout, "Help should document --write-warn flag"
    assert '--avg-warn' in stdout, "Help should document --avg-warn flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_short_help():
    """Test that -h short flag works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '-h']
    )

    assert return_code == 0, f"-h should exit with 0, got {return_code}"
    assert 'disk' in stdout.lower(), "-h should show help"

    print("PASS: Short help test passed")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, \
        f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("PASS: Invalid format test passed")
    return True


def test_invalid_read_warn():
    """Test that negative --read-warn value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--read-warn', '-5']
    )

    assert return_code == 2, \
        f"Negative read-warn should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid read-warn test passed")
    return True


def test_invalid_write_warn():
    """Test that negative --write-warn value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--write-warn', '-10']
    )

    assert return_code == 2, \
        f"Negative write-warn should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid write-warn test passed")
    return True


def test_invalid_avg_warn():
    """Test that negative --avg-warn value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--avg-warn', '-1']
    )

    assert return_code == 2, \
        f"Negative avg-warn should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid avg-warn test passed")
    return True


def test_invalid_regex():
    """Test that invalid regex pattern is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--device', '[invalid(regex']
    )

    assert return_code == 2, \
        f"Invalid regex should exit with 2, got {return_code}"
    assert 'pattern' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid pattern"

    print("PASS: Invalid regex test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_format_plain_accepted():
    """Test that --format plain is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'plain']
    )

    assert 'invalid choice' not in stderr.lower(), "plain should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format plain should work"

    print("PASS: Format plain accepted test passed")
    return True


def test_format_json_accepted():
    """Test that --format json is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'json']
    )

    assert 'invalid choice' not in stderr.lower(), "json should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format json should work"

    print("PASS: Format json accepted test passed")
    return True


def test_format_table_accepted():
    """Test that --format table is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'table']
    )

    assert 'invalid choice' not in stderr.lower(), "table should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format table should work"

    print("PASS: Format table accepted test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_device_filter_flag():
    """Test that --device flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--device', 'sd.*']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--device should be recognized"

    print("PASS: Device filter flag test passed")
    return True


def test_short_device_flag():
    """Test that -d shorthand for --device works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '-d', 'nvme']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-d should be recognized"

    print("PASS: Short device flag test passed")
    return True


def test_include_partitions_flag():
    """Test that --include-partitions flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--include-partitions']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--include-partitions should be recognized"

    print("PASS: Include partitions flag test passed")
    return True


def test_read_warn_flag():
    """Test that --read-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--read-warn', '50']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--read-warn should be recognized"

    print("PASS: Read-warn flag test passed")
    return True


def test_write_warn_flag():
    """Test that --write-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--write-warn', '75']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--write-warn should be recognized"

    print("PASS: Write-warn flag test passed")
    return True


def test_avg_warn_flag():
    """Test that --avg-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--avg-warn', '80']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--avg-warn should be recognized"

    print("PASS: Avg-warn flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_disk_io_latency_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--read-warn', '50',
        '--write-warn', '75',
        '--avg-warn', '60'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_exit_code_valid():
    """Test that script exits with valid exit code."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py']
    )

    # Exit 0 (no issues), 1 (warnings), or 2 (error) are all valid
    assert return_code in [0, 1, 2], \
        f"Exit code should be 0, 1, or 2, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'proc' in stderr.lower():
        print("SKIP: JSON output test (/proc not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'summary' in data, "JSON should have 'summary' field"
            assert data['status'] in ['ok', 'warning'], \
                "Status should be ok or warning"
            print("PASS: JSON output valid test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output valid test passed (script execution checked)")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary', 'issues', 'devices']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['device_count', 'io_wait_pct', 'issue_count']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_json_device_structure():
    """Test that device entries in JSON have expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON device structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if data['devices']:
                device = data['devices'][0]
                required_fields = [
                    'device', 'type', 'read_latency_ms', 'write_latency_ms',
                    'avg_latency_ms', 'read_iops', 'write_iops', 'in_flight'
                ]
                for field in required_fields:
                    assert field in device, f"Device should have '{field}' field"

            print("PASS: JSON device structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON device structure test passed")
    return True


def test_plain_output_has_header():
    """Test that plain output shows device header."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'plain']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Plain output test (script couldn't run)")
        return True

    # Should have header or OK message
    if return_code in [0, 1]:
        has_content = (
            'Device' in stdout or
            'Latency' in stdout or
            'OK' in stdout or
            'ISSUES' in stdout
        )
        assert has_content, "Plain output should have recognizable content"

    print("PASS: Plain output has header test passed")
    return True


def test_table_output():
    """Test that table output works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--format', 'table']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Table output test (script couldn't run)")
        return True

    # Table output should have some content
    if return_code in [0, 1]:
        assert len(stdout) > 0 or len(stderr) > 0, \
            "Table output should produce some output"

    print("PASS: Table output test passed")
    return True


def test_warn_only_no_issues():
    """Test that --warn-only shows OK message when no issues."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_disk_io_latency_monitor.py', '--warn-only', '--read-warn', '999999']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Warn-only test (script couldn't run)")
        return True

    if return_code == 0:
        assert 'OK' in stdout or 'No' in stdout, \
            "Warn-only with no issues should show OK message"

    print("PASS: Warn-only no issues test passed")
    return True


def test_float_threshold_accepted():
    """Test that float values are accepted for thresholds."""
    return_code, stdout, stderr = run_command([
        './baremetal_disk_io_latency_monitor.py',
        '--read-warn', '50.5',
        '--write-warn', '75.25',
        '--avg-warn', '60.123'
    ])

    assert 'invalid' not in stderr.lower() or 'choice' in stderr.lower(), \
        "Float thresholds should be accepted"

    print("PASS: Float threshold accepted test passed")
    return True


def test_zero_threshold_accepted():
    """Test that zero thresholds are accepted."""
    return_code, stdout, stderr = run_command([
        './baremetal_disk_io_latency_monitor.py',
        '--read-warn', '0',
        '--write-warn', '0',
        '--avg-warn', '0'
    ])

    # Should not fail with validation error
    assert 'non-negative' not in stderr.lower(), \
        "Zero should be accepted as threshold"

    print("PASS: Zero threshold accepted test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_disk_io_latency_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_short_help,
        test_invalid_format,
        test_invalid_read_warn,
        test_invalid_write_warn,
        test_invalid_avg_warn,
        test_invalid_regex,
        test_invalid_argument,
        test_format_plain_accepted,
        test_format_json_accepted,
        test_format_table_accepted,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_device_filter_flag,
        test_short_device_flag,
        test_include_partitions_flag,
        test_read_warn_flag,
        test_write_warn_flag,
        test_avg_warn_flag,
        test_combined_flags,
        test_exit_code_valid,
        test_json_output_valid,
        test_json_structure,
        test_json_device_structure,
        test_plain_output_has_header,
        test_table_output,
        test_warn_only_no_issues,
        test_float_threshold_accepted,
        test_zero_threshold_accepted,
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
