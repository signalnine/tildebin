#!/usr/bin/env python3
"""
Tests for baremetal_binfmt_misc_audit.py

These tests validate:
- Argument parsing and flag recognition
- Help message content
- Output format options (plain, json, table)
- Exit code behavior
- JSON output structure

Tests run without requiring specific binfmt_misc configuration.
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
        ['./baremetal_binfmt_misc_audit.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'binfmt' in stdout.lower(), "Help should mention binfmt"
    assert 'qemu' in stdout.lower(), "Help should mention QEMU"
    assert 'wine' in stdout.lower(), "Help should mention Wine"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--allow' in stdout, "Help should document --allow flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_binfmt_misc_audit.py', '--format', fmt]
        )

        # Should succeed (0 or 1 depending on configuration)
        assert return_code in [0, 1], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '-f', 'json']
    )

    assert return_code in [0, 1], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--verbose']
    )

    assert return_code in [0, 1], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '-v']
    )

    assert return_code in [0, 1], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--warn-only']
    )

    assert return_code in [0, 1], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '-w']
    )

    assert return_code in [0, 1], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_allow_flag():
    """Test that --allow flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--allow', 'qemu-arm', 'qemu-aarch64']
    )

    assert return_code in [0, 1], f"Allow flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--allow should be recognized"

    print("PASS: Allow flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_binfmt_misc_audit.py',
        '--format', 'table',
        '--verbose',
        '--allow', 'test-handler'
    ])

    assert return_code in [0, 1], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON with expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'binfmt_misc_enabled', 'handlers', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify handlers is a list
        assert isinstance(data['handlers'], list), "handlers should be a list"

        # Verify healthy is boolean
        assert isinstance(data['healthy'], bool), "healthy should be a boolean"

        # Verify binfmt_misc_enabled is boolean
        assert isinstance(data['binfmt_misc_enabled'], bool), "binfmt_misc_enabled should be a boolean"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_json_analysis_structure():
    """Test that JSON analysis field has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should work, got {return_code}"

    data = json.loads(stdout)

    # Check analysis structure if present
    if 'analysis' in data:
        analysis = data['analysis']
        assert isinstance(analysis, dict), "analysis should be a dictionary"

        expected_fields = ['status', 'issues', 'warnings', 'info']
        for field in expected_fields:
            assert field in analysis, f"analysis should contain '{field}' field"

        assert isinstance(analysis['issues'], list), "issues should be a list"
        assert isinstance(analysis['warnings'], list), "warnings should be a list"
        assert analysis['status'] in ['healthy', 'warning', 'critical'], \
            f"status should be valid, got {analysis['status']}"

    print("PASS: JSON analysis structure test passed")
    return True


def test_json_summary_structure():
    """Test that JSON summary field has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should work, got {return_code}"

    data = json.loads(stdout)

    # Check summary structure if present
    if 'summary' in data:
        summary = data['summary']
        assert isinstance(summary, dict), "summary should be a dictionary"

        expected_fields = ['total_handlers', 'enabled_handlers']
        for field in expected_fields:
            assert field in summary, f"summary should contain '{field}' field"
            assert isinstance(summary[field], int), f"{field} should be an integer"

    print("PASS: JSON summary structure test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'plain']
    )

    assert return_code in [0, 1], f"Plain format should work, got {return_code}"
    assert 'binfmt' in stdout.lower(), "Plain output should mention binfmt"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'table']
    )

    assert return_code in [0, 1], f"Table format should work, got {return_code}"
    # Table output uses + and | for borders
    assert '+' in stdout or '|' in stdout or 'binfmt' in stdout.lower(), \
        "Table output should have table formatting or mention binfmt"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_binfmt_misc_audit.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_binfmt_misc_audit.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_binfmt_misc_audit.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'binfmt' in content.lower(), "Docstring should mention binfmt"
    assert 'security' in content.lower(), "Docstring should mention security"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_timestamp_is_iso_format():
    """Test that timestamp is in ISO format."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should work, got {return_code}"

    data = json.loads(stdout)
    timestamp = data.get('timestamp', '')

    # Should be ISO format like 2024-01-15T10:30:00+00:00
    assert 'T' in timestamp, "Timestamp should be in ISO format (contain T)"
    assert len(timestamp) > 10, "Timestamp should be full ISO format"

    print("PASS: Timestamp ISO format test passed")
    return True


def test_healthy_matches_status():
    """Test that healthy boolean matches status field."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should work, got {return_code}"

    data = json.loads(stdout)

    if 'analysis' in data and 'status' in data['analysis']:
        status = data['analysis']['status']
        if status == 'healthy':
            assert data['healthy'] is True, "healthy should be True when status is healthy"
        else:
            assert data['healthy'] is False, "healthy should be False when status is not healthy"

    print("PASS: Healthy matches status test passed")
    return True


def test_handlers_list_structure():
    """Test that handlers list has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_binfmt_misc_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should work, got {return_code}"

    data = json.loads(stdout)
    handlers = data.get('handlers', [])

    assert isinstance(handlers, list), "handlers should be a list"

    # If there are handlers, verify their structure
    for handler in handlers:
        assert isinstance(handler, dict), "Each handler should be a dictionary"
        assert 'name' in handler, "Handler should have 'name' field"
        assert 'enabled' in handler, "Handler should have 'enabled' field"

    print("PASS: Handlers list structure test passed")
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
        test_allow_flag,
        test_combined_flags,
        test_json_output_valid,
        test_json_analysis_structure,
        test_json_summary_structure,
        test_plain_output_contains_expected_info,
        test_table_output_contains_expected_info,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_timestamp_is_iso_format,
        test_healthy_matches_status,
        test_handlers_list_structure,
    ]

    print(f"Running {len(tests)} tests for baremetal_binfmt_misc_audit.py...")
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
