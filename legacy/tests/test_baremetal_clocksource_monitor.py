#!/usr/bin/env python3
"""
Tests for baremetal_clocksource_monitor.py

These tests validate:
- Argument parsing and flag recognition
- Help message content
- Output format options (plain, json, table)
- Exit code behavior
- JSON output structure

Tests run without requiring specific system clock configuration.
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
        ['./baremetal_clocksource_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'clock' in stdout.lower(), "Help should mention clock"
    assert 'tsc' in stdout.lower(), "Help should mention TSC"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_clocksource_monitor.py', '--format', fmt]
        )

        # Should succeed (0 or 1 depending on configuration), not fail on arg parsing
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '-f', 'json']
    )

    assert return_code in [0, 1, 2], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--verbose']
    )

    assert return_code in [0, 1, 2], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '-v']
    )

    assert return_code in [0, 1, 2], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--warn-only']
    )

    assert return_code in [0, 1, 2], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '-w']
    )

    assert return_code in [0, 1, 2], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_clocksource_monitor.py',
        '--format', 'table',
        '--verbose'
    ])

    assert return_code in [0, 1, 2], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON with expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'json']
    )

    # Exit code 2 means sysfs not available (e.g., in container)
    if return_code == 2:
        print("SKIP: JSON output test skipped (clock source info unavailable)")
        return True

    assert return_code in [0, 1], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'clocksource', 'tsc', 'status',
                          'issues', 'warnings', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify clocksource structure
        assert 'current' in data['clocksource'], "clocksource should have current"
        assert 'available' in data['clocksource'], "clocksource should have available"
        assert isinstance(data['clocksource']['available'], list), \
            "available should be a list"

        # Verify types
        assert isinstance(data['issues'], list), "issues should be a list"
        assert isinstance(data['warnings'], list), "warnings should be a list"
        assert isinstance(data['healthy'], bool), "healthy should be a boolean"
        assert data['status'] in ['healthy', 'warning', 'critical'], \
            f"status should be valid, got {data['status']}"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'plain']
    )

    # Exit code 2 means sysfs not available
    if return_code == 2:
        print("SKIP: Plain output test skipped (clock source info unavailable)")
        return True

    assert return_code in [0, 1], f"Plain format should work, got {return_code}"
    assert 'clock' in stdout.lower(), "Plain output should mention clock"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'table']
    )

    # Exit code 2 means sysfs not available
    if return_code == 2:
        print("SKIP: Table output test skipped (clock source info unavailable)")
        return True

    assert return_code in [0, 1], f"Table format should work, got {return_code}"
    assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_clocksource_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_clocksource_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_clocksource_monitor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'clock' in content.lower(), "Docstring should mention clock"
    assert 'tsc' in content.lower(), "Docstring should mention TSC"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_clocksource_current_not_empty():
    """Test that current clock source is reported when available."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'json']
    )

    # Exit code 2 means sysfs not available
    if return_code == 2:
        print("SKIP: Clock source test skipped (info unavailable)")
        return True

    data = json.loads(stdout)
    current = data['clocksource']['current']

    assert current is not None, "Current clock source should not be None"
    assert len(current) > 0, "Current clock source should not be empty"

    print("PASS: Clock source current not empty test passed")
    return True


def test_available_clocksources_is_list():
    """Test that available clock sources is a non-empty list."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'json']
    )

    # Exit code 2 means sysfs not available
    if return_code == 2:
        print("SKIP: Available clock sources test skipped (info unavailable)")
        return True

    data = json.loads(stdout)
    available = data['clocksource']['available']

    assert isinstance(available, list), "Available should be a list"
    assert len(available) > 0, "Available clock sources should not be empty"

    # Current should be in available list
    current = data['clocksource']['current']
    assert current in available, f"Current '{current}' should be in available list"

    print("PASS: Available clock sources list test passed")
    return True


def test_tsc_info_structure():
    """Test that TSC info has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'json']
    )

    # Exit code 2 means sysfs not available
    if return_code == 2:
        print("SKIP: TSC info test skipped (info unavailable)")
        return True

    data = json.loads(stdout)
    tsc = data['tsc']

    assert isinstance(tsc, dict), "TSC info should be a dictionary"

    # Expected TSC fields (values may be None on some systems)
    expected_fields = ['reliable', 'unstable', 'constant', 'nonstop']
    for field in expected_fields:
        assert field in tsc, f"TSC info should have '{field}' field"

    print("PASS: TSC info structure test passed")
    return True


def test_status_value_valid():
    """Test that status value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'json']
    )

    # Exit code 2 means sysfs not available
    if return_code == 2:
        print("SKIP: Status value test skipped (info unavailable)")
        return True

    data = json.loads(stdout)
    valid_statuses = ['healthy', 'warning', 'critical']

    assert data['status'] in valid_statuses, \
        f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: Status value validation test passed")
    return True


def test_healthy_matches_status():
    """Test that healthy boolean matches status field."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'json']
    )

    # Exit code 2 means sysfs not available
    if return_code == 2:
        print("SKIP: Healthy/status match test skipped (info unavailable)")
        return True

    data = json.loads(stdout)

    if data['status'] == 'healthy':
        assert data['healthy'] is True, "healthy should be True when status is healthy"
    else:
        assert data['healthy'] is False, "healthy should be False when status is not healthy"

    print("PASS: Healthy matches status test passed")
    return True


def test_exit_code_matches_status():
    """Test that exit code matches the status."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_clocksource_monitor.py', '--format', 'json']
    )

    # Exit code 2 means sysfs not available - that's valid
    if return_code == 2:
        print("SKIP: Exit code/status match test skipped (info unavailable)")
        return True

    data = json.loads(stdout)

    if data['status'] == 'healthy':
        assert return_code == 0, f"Exit code should be 0 for healthy status, got {return_code}"
    else:
        assert return_code == 1, f"Exit code should be 1 for non-healthy status, got {return_code}"

    print("PASS: Exit code matches status test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_invalid_format_rejected,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_combined_flags,
        test_json_output_valid,
        test_plain_output_contains_expected_info,
        test_table_output_contains_expected_info,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_clocksource_current_not_empty,
        test_available_clocksources_is_list,
        test_tsc_info_structure,
        test_status_value_valid,
        test_healthy_matches_status,
        test_exit_code_matches_status,
    ]

    print(f"Running {len(tests)} tests for baremetal_clocksource_monitor.py...")
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
