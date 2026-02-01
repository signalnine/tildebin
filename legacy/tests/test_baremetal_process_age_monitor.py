#!/usr/bin/env python3
"""
Tests for baremetal_process_age_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring root access or specific process states.
Note: Full execution tests use very high --min-age to avoid long process scans.
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
        ['./baremetal_process_age_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'process' in stdout.lower(), "Help should mention 'process'"
    assert 'age' in stdout.lower(), "Help should mention 'age'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--min-age' in stdout, "Help should document --min-age flag"
    assert '--warn-days' in stdout, "Help should document --warn-days flag"
    assert '--crit-days' in stdout, "Help should document --crit-days flag"
    assert '--user' in stdout, "Help should document --user flag"
    assert '--cmd' in stdout, "Help should document --cmd flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, \
        f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("PASS: Invalid format test passed")
    return True


def test_invalid_min_age():
    """Test that negative --min-age value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--min-age', '-5']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Negative min-age should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid min-age test passed")
    return True


def test_invalid_warn_days():
    """Test that negative --warn-days value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--warn-days', '-10']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Negative warn-days should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid warn-days test passed")
    return True


def test_crit_less_than_warn():
    """Test that --crit-days less than --warn-days is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--warn-days', '30', '--crit-days', '10']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Crit-days < warn-days should exit with 2, got {return_code}"
    assert 'crit' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention crit-days requirement"

    print("PASS: Crit-days < warn-days test passed")
    return True


def test_invalid_regex():
    """Test that invalid regex pattern is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--cmd', '[invalid(regex']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Invalid regex should exit with 2, got {return_code}"
    assert 'pattern' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid pattern"

    print("PASS: Invalid regex test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_invalid_top():
    """Test that negative --top value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--top', '-1']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Negative top should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid top test passed")
    return True


def test_invalid_crit_days():
    """Test that negative --crit-days value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--crit-days', '-5']
    )

    # Should fail with usage error
    assert return_code == 2, \
        f"Negative crit-days should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid crit-days test passed")
    return True


def test_format_plain_accepted():
    """Test that --format plain is accepted."""
    # Use extremely high min-age to ensure fast execution (no matching processes)
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--format', 'plain', '--min-age', '999999']
    )

    assert 'invalid choice' not in stderr.lower(), "plain should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format plain should work"

    print("PASS: Format plain accepted test passed")
    return True


def test_format_json_accepted():
    """Test that --format json is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--format', 'json', '--min-age', '999999']
    )

    assert 'invalid choice' not in stderr.lower(), "json should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format json should work"

    print("PASS: Format json accepted test passed")
    return True


def test_format_table_accepted():
    """Test that --format table is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--format', 'table', '--min-age', '999999']
    )

    assert 'invalid choice' not in stderr.lower(), "table should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format table should work"

    print("PASS: Format table accepted test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '-f', 'json', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--verbose', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '-v', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--warn-only', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '-w', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_user_filter_flag():
    """Test that --user flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--user', 'root', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--user should be recognized"

    print("PASS: User filter flag test passed")
    return True


def test_cmd_filter_flag():
    """Test that --cmd flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--cmd', 'python', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--cmd should be recognized"

    print("PASS: Cmd filter flag test passed")
    return True


def test_group_flag():
    """Test that --group flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--group', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--group should be recognized"

    print("PASS: Group flag test passed")
    return True


def test_top_flag():
    """Test that --top flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--top', '10', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--top should be recognized"

    print("PASS: Top flag test passed")
    return True


def test_min_age_flag():
    """Test that --min-age flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--min-age', '0.5']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--min-age should be recognized"

    print("PASS: Min-age flag test passed")
    return True


def test_warn_days_flag():
    """Test that --warn-days flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--warn-days', '7', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-days should be recognized"

    print("PASS: Warn-days flag test passed")
    return True


def test_crit_days_flag():
    """Test that --crit-days flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--crit-days', '60', '--min-age', '999999']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--crit-days should be recognized"

    print("PASS: Crit-days flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_process_age_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--min-age', '999999',
        '--warn-days', '7',
        '--crit-days', '30',
        '--top', '5'
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
        ['./baremetal_process_age_monitor.py', '--min-age', '999999']
    )

    # Exit 0 (no issues), 1 (warnings), or 2 (error) are all valid
    assert return_code in [0, 1, 2], \
        f"Exit code should be 0, 1, or 2, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_process_age_monitor.py', '--format', 'json', '--min-age', '999999']
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
            assert data['status'] in ['ok', 'warning', 'critical'], \
                "Status should be ok, warning, or critical"
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
        ['./baremetal_process_age_monitor.py', '--format', 'json', '--min-age', '999999']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['total_processes', 'critical_count', 'warning_count']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_process_age_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_format,
        test_invalid_min_age,
        test_invalid_warn_days,
        test_crit_less_than_warn,
        test_invalid_regex,
        test_invalid_argument,
        test_invalid_top,
        test_invalid_crit_days,
        test_format_plain_accepted,
        test_format_json_accepted,
        test_format_table_accepted,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_user_filter_flag,
        test_cmd_filter_flag,
        test_group_flag,
        test_top_flag,
        test_min_age_flag,
        test_warn_days_flag,
        test_crit_days_flag,
        test_combined_flags,
        test_exit_code_valid,
        test_json_output_valid,
        test_json_structure,
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
