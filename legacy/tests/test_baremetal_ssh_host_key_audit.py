#!/usr/bin/env python3
"""
Tests for baremetal_ssh_host_key_audit.py

These tests validate:
- Argument parsing
- Help message
- Output format options
- Exit codes
- JSON output structure

Tests run without requiring actual SSH host keys or root access.
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
        ['./baremetal_ssh_host_key_audit.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'ssh' in stdout.lower(), "Help should mention SSH"
    assert 'host key' in stdout.lower() or 'host-key' in stdout.lower(), \
        "Help should mention host key"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--ssh-dir' in stdout, "Help should document --ssh-dir flag"
    assert '--max-age' in stdout, "Help should document --max-age flag"
    assert '--warn-only' in stdout, "Help should document --warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_short_help_flag():
    """Test that -h shorthand for --help works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '-h']
    )

    assert return_code == 0, f"Short help flag should exit with 0, got {return_code}"
    assert 'ssh' in stdout.lower(), "Help should mention SSH"

    print("PASS: Short help flag test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_ssh_host_key_audit.py', '--format', fmt]
        )

        # Should succeed (0 or 1 depending on key status), not fail on arg parsing
        assert return_code in [0, 1], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '-f', 'json']
    )

    assert return_code in [0, 1], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_ssh_dir_flag():
    """Test that --ssh-dir flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--ssh-dir', '/etc/ssh']
    )

    assert return_code in [0, 1], f"SSH dir flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--ssh-dir should be recognized"

    print("PASS: SSH dir flag test passed")
    return True


def test_invalid_ssh_dir_rejected():
    """Test that non-existent SSH directory is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--ssh-dir', '/nonexistent/directory']
    )

    assert return_code == 2, f"Non-existent SSH dir should exit with 2, got {return_code}"
    assert 'not found' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for non-existent directory"

    print("PASS: Invalid SSH dir rejection test passed")
    return True


def test_max_age_flag():
    """Test that --max-age flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--max-age', '365']
    )

    assert return_code in [0, 1], f"Max age flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--max-age should be recognized"

    print("PASS: Max age flag test passed")
    return True


def test_invalid_max_age_rejected():
    """Test that invalid max-age values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--max-age', '0']
    )

    assert return_code == 2, f"Zero max-age should exit with 2, got {return_code}"
    assert 'positive' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid max-age"

    print("PASS: Invalid max-age rejection test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--warn-only']
    )

    assert return_code in [0, 1], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '-w']
    )

    assert return_code in [0, 1], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--verbose']
    )

    assert return_code in [0, 1], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '-v']
    )

    assert return_code in [0, 1], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_ssh_host_key_audit.py',
        '--format', 'table',
        '--max-age', '365',
        '--verbose'
    ])

    assert return_code in [0, 1], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON with expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'ssh_dir', 'summary', 'keys',
                          'issues', 'warnings', 'status', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify summary structure
        assert isinstance(data['summary'], dict), "summary should be a dict"
        summary_fields = ['total_keys', 'secure_keys', 'weak_keys', 'permission_issues']
        for field in summary_fields:
            assert field in data['summary'], f"summary should contain '{field}'"

        # Verify types
        assert isinstance(data['keys'], list), "keys should be a list"
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
        ['./baremetal_ssh_host_key_audit.py', '--format', 'plain']
    )

    assert return_code in [0, 1], f"Plain format should work, got {return_code}"
    assert 'ssh' in stdout.lower(), "Plain output should mention SSH"
    assert 'host key' in stdout.lower() or 'keys' in stdout.lower(), \
        "Plain output should mention keys"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'table']
    )

    assert return_code in [0, 1], f"Table format should work, got {return_code}"
    assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_ssh_host_key_audit.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_ssh_host_key_audit.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_ssh_host_key_audit.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'ssh' in content.lower(), "Docstring should mention SSH"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_status_value_valid():
    """Test that status value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    valid_statuses = ['healthy', 'warning', 'critical']

    assert data['status'] in valid_statuses, \
        f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: Status value validation test passed")
    return True


def test_keys_have_expected_structure():
    """Test that keys in JSON have expected structure when present."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    keys = data['keys']

    if keys:  # If any keys found
        key = keys[0]
        expected_fields = ['path', 'filename', 'exists', 'issues', 'warnings']
        for field in expected_fields:
            assert field in key, f"Key should have '{field}' field"

        assert isinstance(key['issues'], list), "issues should be a list"
        assert isinstance(key['warnings'], list), "warnings should be a list"

    print("PASS: Keys structure test passed")
    return True


def test_summary_values_non_negative():
    """Test that summary values are non-negative integers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    summary = data['summary']

    for field in ['total_keys', 'secure_keys', 'weak_keys', 'permission_issues']:
        assert isinstance(summary[field], int), f"{field} should be an integer"
        assert summary[field] >= 0, f"{field} should be non-negative"

    print("PASS: Summary values test passed")
    return True


def test_ssh_dir_in_output():
    """Test that SSH directory appears in output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'json']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    assert data['ssh_dir'] == '/etc/ssh', "Default SSH dir should be /etc/ssh"

    print("PASS: SSH dir in output test passed")
    return True


def test_custom_ssh_dir_in_output():
    """Test that custom SSH directory appears in output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_ssh_host_key_audit.py', '--format', 'json', '--ssh-dir', '/etc/ssh']
    )

    assert return_code in [0, 1], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)
    assert data['ssh_dir'] == '/etc/ssh', "SSH dir should match argument"

    print("PASS: Custom SSH dir in output test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_short_help_flag,
        test_format_flag_recognized,
        test_short_format_flag,
        test_invalid_format_rejected,
        test_ssh_dir_flag,
        test_invalid_ssh_dir_rejected,
        test_max_age_flag,
        test_invalid_max_age_rejected,
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
        test_status_value_valid,
        test_keys_have_expected_structure,
        test_summary_values_non_negative,
        test_ssh_dir_in_output,
        test_custom_ssh_dir_in_output,
    ]

    print(f"Running {len(tests)} tests for baremetal_ssh_host_key_audit.py...")
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
