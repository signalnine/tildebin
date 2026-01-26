#!/usr/bin/env python3
"""
Tests for baremetal_load_average_monitor.py

These tests validate:
- Argument parsing
- Help message
- Output format options
- Threshold validation
- Exit codes

Tests run without requiring specific system load conditions.
"""

import subprocess
import sys
import json
import os
import stat


def run_command(args, timeout=5):
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
        ['./baremetal_load_average_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'load average' in stdout.lower(), "Help should mention load average"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warning' in stdout, "Help should document --warning flag"
    assert '--critical' in stdout, "Help should document --critical flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_load_average_monitor.py', '--format', fmt]
        )

        # Should succeed (0 or 1 depending on load), not fail on arg parsing
        assert return_code in [0, 1], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '-f', 'json']
    )

    assert return_code in [0, 1], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_warning_threshold_flag():
    """Test that --warning flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--warning', '0.5']
    )

    assert return_code in [0, 1], f"Warning flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warning should be recognized"

    print("PASS: Warning threshold flag test passed")
    return True


def test_critical_threshold_flag():
    """Test that --critical flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--critical', '2.0']
    )

    assert return_code in [0, 1], f"Critical flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--critical should be recognized"

    print("PASS: Critical threshold flag test passed")
    return True


def test_short_threshold_flags():
    """Test that -W and -C shorthands work."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '-W', '0.5', '-C', '1.5']
    )

    assert return_code in [0, 1], f"Short threshold flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-W and -C should be recognized"

    print("PASS: Short threshold flags test passed")
    return True


def test_invalid_threshold_warning_gte_critical():
    """Test that warning >= critical is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--warning', '1.0', '--critical', '1.0']
    )

    assert return_code == 2, f"Equal thresholds should exit with 2, got {return_code}"
    assert 'threshold' in stderr.lower(), "Should mention threshold in error"

    print("PASS: Invalid threshold (warning >= critical) test passed")
    return True


def test_invalid_negative_threshold():
    """Test that negative thresholds are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--warning', '-0.5']
    )

    assert return_code == 2, f"Negative threshold should exit with 2, got {return_code}"
    assert 'threshold' in stderr.lower() or 'negative' in stderr.lower(), \
        "Should mention threshold error"

    print("PASS: Negative threshold rejection test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--warn-only']
    )

    assert return_code in [0, 1], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '-w']
    )

    assert return_code in [0, 1], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--verbose']
    )

    assert return_code in [0, 1], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '-v']
    )

    assert return_code in [0, 1], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_load_average_monitor.py',
        '--format', 'table',
        '--warning', '0.5',
        '--critical', '1.5',
        '--verbose'
    ])

    assert return_code in [0, 1], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON with expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'cpu', 'load_averages', 'normalized_load',
                         'trend', 'status', 'issues', 'warnings', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify load_averages structure
        assert '1min' in data['load_averages'], "load_averages should have 1min"
        assert '5min' in data['load_averages'], "load_averages should have 5min"
        assert '15min' in data['load_averages'], "load_averages should have 15min"

        # Verify cpu structure
        assert 'online' in data['cpu'], "cpu should have online count"
        assert 'configured' in data['cpu'], "cpu should have configured count"

        # Verify types
        assert isinstance(data['issues'], list), "issues should be a list"
        assert isinstance(data['warnings'], list), "warnings should be a list"
        assert isinstance(data['healthy'], bool), "healthy should be a boolean"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'plain']
    )

    assert return_code in [0, 1], f"Plain format should work, got {return_code}"
    assert 'load' in stdout.lower(), "Plain output should mention load"
    assert 'cpu' in stdout.lower(), "Plain output should mention CPU"
    assert 'min' in stdout.lower(), "Plain output should show minute intervals"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'table']
    )

    assert return_code in [0, 1], f"Table format should work, got {return_code}"
    assert 'load' in stdout.lower(), "Table output should mention load"
    assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_load_average_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_load_average_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_load_average_monitor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'load' in content.lower(), "Docstring should mention load"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_load_values_are_numeric():
    """Test that load values in JSON output are numeric."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    load = data['load_averages']

    assert isinstance(load['1min'], (int, float)), "1min load should be numeric"
    assert isinstance(load['5min'], (int, float)), "5min load should be numeric"
    assert isinstance(load['15min'], (int, float)), "15min load should be numeric"

    # Load values should be non-negative
    assert load['1min'] >= 0, "1min load should be non-negative"
    assert load['5min'] >= 0, "5min load should be non-negative"
    assert load['15min'] >= 0, "15min load should be non-negative"

    print("PASS: Load values numeric test passed")
    return True


def test_cpu_count_reasonable():
    """Test that CPU count in JSON output is reasonable."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    cpu = data['cpu']

    assert cpu['online'] > 0, "Should have at least 1 online CPU"
    assert cpu['configured'] >= cpu['online'], "Configured CPUs >= online CPUs"
    assert cpu['offline'] >= 0, "Offline CPUs should be non-negative"
    assert cpu['offline'] == cpu['configured'] - cpu['online'], \
        "Offline count should match configured - online"

    print("PASS: CPU count reasonableness test passed")
    return True


def test_trend_value_valid():
    """Test that trend value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    valid_trends = ['increasing', 'decreasing', 'stable']

    assert data['trend'] in valid_trends, \
        f"Trend should be one of {valid_trends}, got {data['trend']}"

    print("PASS: Trend value validation test passed")
    return True


def test_status_value_valid():
    """Test that status value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    valid_statuses = ['healthy', 'warning', 'critical']

    assert data['status'] in valid_statuses, \
        f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: Status value validation test passed")
    return True


def test_high_threshold_no_warnings():
    """Test that very high thresholds produce no warnings on typical systems."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_load_average_monitor.py', '--format', 'json',
         '--warning', '100', '--critical', '200']
    )

    assert return_code == 0, f"High thresholds should produce healthy status, got {return_code}"

    data = json.loads(stdout)
    assert data['healthy'] is True, "Should be healthy with very high thresholds"
    assert len(data['issues']) == 0, "Should have no issues with very high thresholds"

    print("PASS: High threshold no warnings test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_invalid_format_rejected,
        test_warning_threshold_flag,
        test_critical_threshold_flag,
        test_short_threshold_flags,
        test_invalid_threshold_warning_gte_critical,
        test_invalid_negative_threshold,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_combined_flags,
        test_json_output_valid,
        test_plain_output_contains_expected_info,
        test_table_output_contains_expected_info,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_load_values_are_numeric,
        test_cpu_count_reasonable,
        test_trend_value_valid,
        test_status_value_valid,
        test_high_threshold_no_warnings,
    ]

    print(f"Running {len(tests)} tests for baremetal_load_average_monitor.py...")
    print()

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"FAIL: {test.__name__} failed: {e}")
            failed.append(test.__name__)
        except Exception as e:
            print(f"FAIL: {test.__name__} error: {e}")
            failed.append(test.__name__)

    print()
    if failed:
        print(f"Failed tests: {', '.join(failed)}")
        return 1
    else:
        print(f"All {len(tests)} tests passed!")
        return 0


if __name__ == '__main__':
    sys.exit(main())
