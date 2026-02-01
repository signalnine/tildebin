#!/usr/bin/env python3
"""
Tests for baremetal_sudoers_audit.py

These tests validate:
- Argument parsing
- Help message
- Output format options
- JSON output structure
- Exit codes
- Pattern detection logic

Tests run without requiring root access or actual sudoers files.
"""

import subprocess
import sys
import json
import os
import stat


def run_command(args, timeout=10):
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
        ['./baremetal_sudoers_audit.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'sudoers' in stdout.lower(), "Help should mention sudoers"
    assert 'audit' in stdout.lower(), "Help should mention audit"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--no-syntax' in stdout, "Help should document --no-syntax flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"
    assert 'NOPASSWD' in stdout, "Help should mention NOPASSWD check"
    assert 'env_reset' in stdout, "Help should mention env_reset check"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_sudoers_audit.py', '--format', fmt]
        )

        # Should succeed (0, 1, or 2 based on sudoers access)
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '-f', 'json']
    )

    assert return_code in [0, 1, 2], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--warn-only']
    )

    assert return_code in [0, 1, 2], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '-w']
    )

    assert return_code in [0, 1, 2], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_no_syntax_flag():
    """Test that --no-syntax flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--no-syntax']
    )

    assert return_code in [0, 1, 2], f"No-syntax flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--no-syntax should be recognized"

    print("PASS: No-syntax flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--verbose']
    )

    assert return_code in [0, 1, 2], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '-v']
    )

    assert return_code in [0, 1, 2], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_sudoers_audit.py',
        '--format', 'table',
        '--warn-only',
        '--no-syntax',
        '--verbose'
    ])

    assert return_code in [0, 1, 2], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1, 2], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify types
        assert isinstance(data['healthy'], bool), "healthy should be a boolean"

        # If no error, should have these fields
        if 'error' not in data:
            assert 'status' in data, "Should have status when no error"
            assert 'issues' in data, "Should have issues list"
            assert 'summary' in data, "Should have summary"
            assert isinstance(data['issues'], list), "issues should be a list"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_json_status_values():
    """Test that JSON status values are valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    data = json.loads(stdout)

    if 'status' in data:
        valid_statuses = ['healthy', 'warning', 'critical']
        assert data['status'] in valid_statuses, \
            f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: JSON status values test passed")
    return True


def test_json_summary_structure():
    """Test that JSON summary has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    data = json.loads(stdout)

    if 'summary' in data:
        summary = data['summary']
        expected_keys = ['critical', 'warning', 'info']
        for key in expected_keys:
            assert key in summary, f"Summary should contain '{key}'"
            assert isinstance(summary[key], int), f"Summary['{key}'] should be an integer"

    print("PASS: JSON summary structure test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'plain']
    )

    assert return_code in [0, 1, 2], f"Plain format should work, got {return_code}"

    # Check for output content
    output = stdout + stderr
    assert ('sudoers' in output.lower() or 'audit' in output.lower() or
            'error' in output.lower()), \
        "Output should mention sudoers, audit, or error"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_format():
    """Test that table output has table formatting."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'table']
    )

    assert return_code in [0, 1, 2], f"Table format should work, got {return_code}"

    # Table output should have table formatting characters
    if return_code != 2:  # If not an error exit
        assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output format test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_sudoers_audit.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_sudoers_audit.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_sudoers_audit.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'sudoers' in content.lower(), "Docstring should mention sudoers"
    assert 'NOPASSWD' in content, "Docstring should mention NOPASSWD"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_graceful_handling_no_access():
    """Test graceful handling when sudoers files can't be read."""
    # Script should handle permission errors gracefully
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    # Should either work or report access issues, not crash
    assert return_code in [0, 1, 2], f"Should handle access issues gracefully, got {return_code}"

    # JSON should always be valid
    try:
        data = json.loads(stdout)
        assert 'timestamp' in data, "JSON should have timestamp"
    except json.JSONDecodeError:
        # If JSON output, it should be valid
        if '--format' in str(run_command) and 'json' in str(run_command):
            raise AssertionError("JSON output should be valid")

    print("PASS: Graceful no-access handling test passed")
    return True


def test_issue_structure_in_json():
    """Test that issues in JSON output have expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    data = json.loads(stdout)

    if 'issues' in data and data['issues']:
        for issue in data['issues']:
            assert 'type' in issue, "Issue should have 'type' field"
            assert 'severity' in issue, "Issue should have 'severity' field"
            # These are optional but commonly present
            if 'severity' in issue:
                valid_severities = ['critical', 'warning', 'info', 'error']
                assert issue['severity'] in valid_severities, \
                    f"Severity should be valid, got {issue['severity']}"

    print("PASS: Issue structure test passed")
    return True


def test_files_checked_in_json():
    """Test that files_checked is present in JSON output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    data = json.loads(stdout)

    # If not an error condition, should list files checked
    if 'error' not in data:
        assert 'files_checked' in data, "Should list files_checked"
        assert isinstance(data['files_checked'], list), "files_checked should be a list"

    print("PASS: Files checked in JSON test passed")
    return True


def test_defaults_info_in_json():
    """Test that defaults info is present in JSON output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    data = json.loads(stdout)

    # If not an error condition, should have defaults info
    if 'error' not in data and 'defaults' in data:
        defaults = data['defaults']
        expected_keys = ['has_env_reset', 'has_secure_path', 'has_requiretty']
        for key in expected_keys:
            assert key in defaults, f"Defaults should contain '{key}'"
            assert isinstance(defaults[key], bool), f"defaults['{key}'] should be boolean"

    print("PASS: Defaults info in JSON test passed")
    return True


def test_no_crash_on_missing_sudoers():
    """Test that script doesn't crash if sudoers doesn't exist."""
    # This test verifies error handling, not the actual check
    return_code, stdout, stderr = run_command(
        ['./baremetal_sudoers_audit.py', '--format', 'json']
    )

    # Should not crash (-1 would indicate crash/timeout)
    assert return_code >= 0, "Script should not crash"
    assert return_code <= 2, f"Exit code should be 0, 1, or 2, got {return_code}"

    print("PASS: No crash on missing sudoers test passed")
    return True


def test_patterns_recognized():
    """Test that the script recognizes security patterns in documentation."""
    with open('./baremetal_sudoers_audit.py', 'r') as f:
        content = f.read()

    # Verify key patterns are implemented
    assert 'NOPASSWD' in content, "Should check for NOPASSWD"
    assert 'ALL' in content, "Should check for ALL commands"
    assert 'env_reset' in content, "Should check for env_reset"
    assert 'secure_path' in content, "Should check for secure_path"
    assert 'requiretty' in content, "Should check for requiretty"
    assert 'timestamp_timeout' in content, "Should check for timestamp_timeout"

    print("PASS: Patterns recognized test passed")
    return True


def test_permission_checks_implemented():
    """Test that file permission checking is implemented."""
    with open('./baremetal_sudoers_audit.py', 'r') as f:
        content = f.read()

    # Verify permission checking is implemented
    assert 'st_mode' in content or 'stat' in content, "Should check file permissions"
    assert 'st_uid' in content, "Should check file ownership"
    assert '0440' in content or '0o440' in content, "Should reference correct permissions"

    print("PASS: Permission checks implemented test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_invalid_format_rejected,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_no_syntax_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_combined_flags,
        test_json_output_structure,
        test_json_status_values,
        test_json_summary_structure,
        test_plain_output_contains_expected_info,
        test_table_output_format,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_graceful_handling_no_access,
        test_issue_structure_in_json,
        test_files_checked_in_json,
        test_defaults_info_in_json,
        test_no_crash_on_missing_sudoers,
        test_patterns_recognized,
        test_permission_checks_implemented,
    ]

    print(f"Running {len(tests)} tests for baremetal_sudoers_audit.py...")
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
