#!/usr/bin/env python3
"""
Tests for baremetal_cpu_isolation_auditor.py

These tests validate:
- Argument parsing and flag recognition
- Help message content
- Output format options (plain, json, table)
- Exit code behavior
- JSON output structure

Tests run without requiring specific CPU isolation configuration.
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
        ['./baremetal_cpu_isolation_auditor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'isolation' in stdout.lower(), "Help should mention isolation"
    assert 'cpu' in stdout.lower(), "Help should mention CPU"
    assert 'isolcpus' in stdout.lower(), "Help should mention isolcpus parameter"
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
            ['./baremetal_cpu_isolation_auditor.py', '--format', fmt]
        )

        # Should succeed (0 or 1 depending on configuration), or 2 if info unavailable
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '-f', 'json']
    )

    assert return_code in [0, 1, 2], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--verbose']
    )

    assert return_code in [0, 1, 2], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '-v']
    )

    assert return_code in [0, 1, 2], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--warn-only']
    )

    assert return_code in [0, 1, 2], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '-w']
    )

    assert return_code in [0, 1, 2], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_cpu_isolation_auditor.py',
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
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    # Exit code 2 means required info not available
    if return_code == 2:
        print("SKIP: JSON output test skipped (CPU info unavailable)")
        return True

    assert return_code in [0, 1], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'online_cpus', 'cpu_count', 'isolation',
                          'status', 'issues', 'warnings', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # Verify types
        assert isinstance(data['online_cpus'], list), "online_cpus should be a list"
        assert isinstance(data['cpu_count'], int), "cpu_count should be an integer"
        assert isinstance(data['isolation'], dict), "isolation should be a dictionary"
        assert isinstance(data['issues'], list), "issues should be a list"
        assert isinstance(data['warnings'], list), "warnings should be a list"
        assert isinstance(data['healthy'], bool), "healthy should be a boolean"
        assert data['status'] in ['ok', 'warning', 'error', 'none'], \
            f"status should be valid, got {data['status']}"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_json_isolation_structure():
    """Test that JSON output has proper isolation structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: JSON isolation structure test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)
    isolation = data['isolation']

    # Check isolation structure
    assert 'isolcpus' in isolation, "isolation should have 'isolcpus' field"
    assert 'nohz_full' in isolation, "isolation should have 'nohz_full' field"
    assert 'rcu_nocbs' in isolation, "isolation should have 'rcu_nocbs' field"

    assert isinstance(isolation['isolcpus'], list), "isolcpus should be a list"
    assert isinstance(isolation['nohz_full'], list), "nohz_full should be a list"
    assert isinstance(isolation['rcu_nocbs'], list), "rcu_nocbs should be a list"

    print("PASS: JSON isolation structure test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'plain']
    )

    if return_code == 2:
        print("SKIP: Plain output test skipped (CPU info unavailable)")
        return True

    assert return_code in [0, 1], f"Plain format should work, got {return_code}"
    assert 'cpu' in stdout.lower(), "Plain output should mention CPU"
    assert 'isolation' in stdout.lower(), "Plain output should mention isolation"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'table']
    )

    if return_code == 2:
        print("SKIP: Table output test skipped (CPU info unavailable)")
        return True

    assert return_code in [0, 1], f"Table format should work, got {return_code}"
    assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_cpu_isolation_auditor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_cpu_isolation_auditor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_cpu_isolation_auditor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'isolation' in content.lower(), "Docstring should mention isolation"
    assert 'cpu' in content.lower(), "Docstring should mention CPU"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_status_value_valid():
    """Test that status value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Status value test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)
    valid_statuses = ['ok', 'warning', 'error', 'none']

    assert data['status'] in valid_statuses, \
        f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: Status value validation test passed")
    return True


def test_healthy_matches_status():
    """Test that healthy boolean matches status field."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Healthy/status match test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)

    if data['status'] in ['ok', 'none']:
        assert data['healthy'] is True, "healthy should be True when status is ok/none"
    else:
        assert data['healthy'] is False, "healthy should be False when status is warning/error"

    print("PASS: Healthy matches status test passed")
    return True


def test_exit_code_matches_status():
    """Test that exit code matches the status."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Exit code/status match test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)

    if data['status'] in ['ok', 'none']:
        assert return_code == 0, f"Exit code should be 0 for {data['status']} status, got {return_code}"
    else:
        assert return_code == 1, f"Exit code should be 1 for {data['status']} status, got {return_code}"

    print("PASS: Exit code matches status test passed")
    return True


def test_cpu_count_matches_list():
    """Test that cpu_count matches online_cpus list length."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: CPU count match test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)

    assert data['cpu_count'] == len(data['online_cpus']), \
        f"cpu_count ({data['cpu_count']}) should match online_cpus length ({len(data['online_cpus'])})"

    print("PASS: CPU count matches list test passed")
    return True


def test_verbose_output_more_detailed():
    """Test that verbose output includes additional details."""
    return_code_normal, stdout_normal, _ = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'plain']
    )

    return_code_verbose, stdout_verbose, _ = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'plain', '--verbose']
    )

    if return_code_normal == 2 or return_code_verbose == 2:
        print("SKIP: Verbose comparison test skipped (CPU info unavailable)")
        return True

    # Verbose should have same or more content
    assert len(stdout_verbose) >= len(stdout_normal), \
        "Verbose output should have at least as much content as normal"

    print("PASS: Verbose output more detailed test passed")
    return True


def test_info_field_present():
    """Test that info messages field is included in JSON output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Info field test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)

    assert 'info' in data, "JSON should contain 'info' field"
    assert isinstance(data['info'], list), "info should be a list"

    print("PASS: Info field present test passed")
    return True


def test_online_cpus_are_integers():
    """Test that online_cpus contains integers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Online CPUs integers test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)

    for cpu in data['online_cpus']:
        assert isinstance(cpu, int), f"CPU ID should be integer, got {type(cpu)}"

    print("PASS: Online CPUs are integers test passed")
    return True


def test_isolation_lists_contain_integers():
    """Test that isolation CPU lists contain only integers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Isolation integers test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)
    isolation = data['isolation']

    for field in ['isolcpus', 'nohz_full', 'rcu_nocbs']:
        for cpu in isolation[field]:
            assert isinstance(cpu, int), f"{field} should contain integers, got {type(cpu)}"

    print("PASS: Isolation lists contain integers test passed")
    return True


def test_mentions_nohz_full_in_help():
    """Test that help mentions nohz_full parameter."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--help']
    )

    assert 'nohz_full' in stdout, "Help should mention nohz_full parameter"

    print("PASS: nohz_full in help test passed")
    return True


def test_mentions_rcu_nocbs_in_help():
    """Test that help mentions rcu_nocbs parameter."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--help']
    )

    assert 'rcu_nocbs' in stdout, "Help should mention rcu_nocbs parameter"

    print("PASS: rcu_nocbs in help test passed")
    return True


def test_cmdline_raw_field_present():
    """Test that cmdline_raw field is present in isolation output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_cpu_isolation_auditor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: cmdline_raw field test skipped (CPU info unavailable)")
        return True

    data = json.loads(stdout)

    assert 'cmdline_raw' in data['isolation'], \
        "isolation should contain 'cmdline_raw' field"
    assert isinstance(data['isolation']['cmdline_raw'], dict), \
        "cmdline_raw should be a dictionary"

    print("PASS: cmdline_raw field present test passed")
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
        test_json_isolation_structure,
        test_plain_output_contains_expected_info,
        test_table_output_contains_expected_info,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_status_value_valid,
        test_healthy_matches_status,
        test_exit_code_matches_status,
        test_cpu_count_matches_list,
        test_verbose_output_more_detailed,
        test_info_field_present,
        test_online_cpus_are_integers,
        test_isolation_lists_contain_integers,
        test_mentions_nohz_full_in_help,
        test_mentions_rcu_nocbs_in_help,
        test_cmdline_raw_field_present,
    ]

    print(f"Running {len(tests)} tests for baremetal_cpu_isolation_auditor.py...")
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
    passed = len(tests) - len(failed)
    total = len(tests)
    if failed:
        print(f"Failed tests: {', '.join(failed)}")
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
