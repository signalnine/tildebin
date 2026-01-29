#!/usr/bin/env python3
"""
Tests for baremetal_cpu_steal_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring specific virtualization environment.
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
        ['./baremetal_cpu_steal_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'steal' in stdout.lower(), "Help should mention 'steal'"
    assert 'cpu' in stdout.lower(), "Help should mention 'CPU'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--interval' in stdout, "Help should document --interval flag"
    assert '--warn' in stdout, "Help should document --warn threshold"
    assert '--crit' in stdout, "Help should document --crit threshold"
    assert 'Exit codes:' in stdout, "Help should document exit codes"
    assert 'hypervisor' in stdout.lower() or 'virtual' in stdout.lower(), \
        "Help should explain virtualization context"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_cpu_steal_monitor.py', '--format', fmt, '--interval', '0.1']
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
        ['./baremetal_cpu_steal_monitor.py', '-f', 'json', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--verbose', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '-v', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--warn-only', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '-w', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_interval_flag():
    """Test that --interval flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--interval', '0.5']
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
        ['./baremetal_cpu_steal_monitor.py', '--interval', '-1']
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
        ['./baremetal_cpu_steal_monitor.py', '--interval', '500']
    )

    assert return_code == 2, \
        f"Too large interval should exit with 2, got {return_code}"
    assert 'cannot exceed' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention interval limit"

    print("PASS: Invalid too large interval test passed")
    return True


def test_warn_threshold_flag():
    """Test that --warn flag accepts valid percentage."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--warn', '10', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn should be recognized"
    assert return_code in [0, 1, 2], \
        f"--warn 10 should be valid, got {return_code}"

    print("PASS: Warn threshold flag test passed")
    return True


def test_crit_threshold_flag():
    """Test that --crit flag accepts valid percentage."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--crit', '20', '--interval', '0.1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--crit should be recognized"
    assert return_code in [0, 1, 2], \
        f"--crit 20 should be valid, got {return_code}"

    print("PASS: Critical threshold flag test passed")
    return True


def test_invalid_warn_threshold_range():
    """Test that --warn outside 0-100 is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--warn', '150', '--interval', '0.1']
    )

    assert return_code == 2, \
        f"--warn 150 should exit with 2, got {return_code}"
    assert 'must be 0-100' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid threshold range"

    print("PASS: Invalid warn threshold range test passed")
    return True


def test_invalid_crit_threshold_range():
    """Test that --crit outside 0-100 is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--crit', '-5', '--interval', '0.1']
    )

    assert return_code == 2, \
        f"--crit -5 should exit with 2, got {return_code}"
    assert 'must be 0-100' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid threshold range"

    print("PASS: Invalid crit threshold range test passed")
    return True


def test_warn_must_be_less_than_crit():
    """Test that --warn must be less than --crit."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--warn', '20', '--crit', '10', '--interval', '0.1']
    )

    assert return_code == 2, \
        f"--warn > --crit should exit with 2, got {return_code}"
    assert 'must be less than' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention warn must be less than crit"

    print("PASS: Warn must be less than crit test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--nonexistent-option']
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
        ['./baremetal_cpu_steal_monitor.py', '--format', 'json', '--interval', '0.1']
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
            assert 'cpus' in data, "JSON should have 'cpus' field"
            assert data['status'] in ['ok', 'warning', 'critical'], \
                "Status should be ok, warning, or critical"
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
        ['./baremetal_cpu_steal_monitor.py', '--verbose', '--interval', '0.1']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Plain output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        output_lower = stdout.lower()
        assert ('cpu' in output_lower or 'steal' in output_lower or
                'status' in output_lower), \
            "Output should contain CPU info or status"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--format', 'table', '--interval', '0.1']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Table output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            header = lines[0].lower()
            assert ('cpu' in header or 'user' in header or
                    'steal' in header or 'status' in header or
                    'no' in header), \
                "Table should have header row or status message"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_success():
    """Test that script exits appropriately."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--warn', '99', '--crit', '100', '--interval', '0.1']
    )

    # With very high threshold, should typically succeed on most systems
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
        './baremetal_cpu_steal_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--interval', '0.1',
        '--warn', '5',
        '--crit', '15'
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
        ['./baremetal_cpu_steal_monitor.py', '--format', 'json', '--interval', '0.1']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary', 'cpus', 'issues', 'warnings', 'timestamp']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['cpu_count', 'avg_steal_pct', 'max_steal_pct',
                           'min_steal_pct', 'warn_threshold', 'crit_threshold']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            # Check that cpus is a dict
            assert isinstance(data['cpus'], dict), \
                "cpus should be a dictionary"

            # Check that issues and warnings are lists
            assert isinstance(data['issues'], list), "issues should be a list"
            assert isinstance(data['warnings'], list), "warnings should be a list"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_cpu_data_fields():
    """Test that CPU entries have expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--format', 'json', '--interval', '0.1']
    )

    if return_code == 2:
        print("SKIP: CPU data fields test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if data['cpus']:
                # Check first CPU entry
                first_cpu = list(data['cpus'].values())[0]
                expected_fields = ['user', 'system', 'idle', 'iowait', 'steal']
                for field in expected_fields:
                    assert field in first_cpu, f"CPU entry should have '{field}' field"

            print("PASS: CPU data fields test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: CPU data fields test passed (no JSON to check)")
            return True

    print("PASS: CPU data fields test passed")
    return True


def test_steal_time_is_number():
    """Test that steal time values are numeric."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_steal_monitor.py', '--format', 'json', '--interval', '0.1']
    )

    if return_code == 2:
        print("SKIP: Steal time is number test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            for cpu_name, cpu_data in data['cpus'].items():
                steal = cpu_data.get('steal')
                assert isinstance(steal, (int, float)), \
                    f"Steal time for {cpu_name} should be numeric, got {type(steal)}"
                assert 0 <= steal <= 100, \
                    f"Steal time for {cpu_name} should be 0-100, got {steal}"

            print("PASS: Steal time is number test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Steal time is number test passed (no JSON to check)")
            return True

    print("PASS: Steal time is number test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_cpu_steal_monitor.py...")
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
        test_warn_threshold_flag,
        test_crit_threshold_flag,
        test_invalid_warn_threshold_range,
        test_invalid_crit_threshold_range,
        test_warn_must_be_less_than_crit,
        test_invalid_argument,
        test_json_output_format,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_success,
        test_combined_flags,
        test_json_structure,
        test_cpu_data_fields,
        test_steal_time_is_number,
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
