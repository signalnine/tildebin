#!/usr/bin/env python3
"""
Tests for baremetal_proc_pressure_monitor.py

These tests validate:
- Argument parsing
- Help message
- Output format options
- Threshold validation
- Exit codes
- JSON output structure

Tests run without requiring specific PSI support (graceful handling of unavailable PSI).
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
        ['./baremetal_proc_pressure_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'pressure' in stdout.lower(), "Help should mention pressure"
    assert 'psi' in stdout.lower(), "Help should mention PSI"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-some' in stdout, "Help should document --warn-some flag"
    assert '--crit-some' in stdout, "Help should document --crit-some flag"
    assert '--warn-full' in stdout, "Help should document --warn-full flag"
    assert '--crit-full' in stdout, "Help should document --crit-full flag"
    assert '--resource' in stdout, "Help should document --resource flag"
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
            ['./baremetal_proc_pressure_monitor.py', '--format', fmt]
        )

        # Should succeed (0, 1, or 2 if PSI unavailable), not fail on arg parsing
        assert return_code in [0, 1, 2], f"Format {fmt} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Format {fmt} should be a valid choice"

    print("PASS: Format flag recognition test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '-f', 'json']
    )

    assert return_code in [0, 1, 2], f"Short format flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"

    print("PASS: Short format flag test passed")
    return True


def test_invalid_format_rejected():
    """Test that invalid format values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid format"

    print("PASS: Invalid format rejection test passed")
    return True


def test_warn_some_threshold_flag():
    """Test that --warn-some flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--warn-some', '5.0']
    )

    assert return_code in [0, 1, 2], f"Warn-some flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-some should be recognized"

    print("PASS: Warn-some threshold flag test passed")
    return True


def test_crit_some_threshold_flag():
    """Test that --crit-some flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--crit-some', '30.0']
    )

    assert return_code in [0, 1, 2], f"Crit-some flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--crit-some should be recognized"

    print("PASS: Crit-some threshold flag test passed")
    return True


def test_warn_full_threshold_flag():
    """Test that --warn-full flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--warn-full', '3.0']
    )

    assert return_code in [0, 1, 2], f"Warn-full flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-full should be recognized"

    print("PASS: Warn-full threshold flag test passed")
    return True


def test_crit_full_threshold_flag():
    """Test that --crit-full flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--crit-full', '15.0']
    )

    assert return_code in [0, 1, 2], f"Crit-full flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--crit-full should be recognized"

    print("PASS: Crit-full threshold flag test passed")
    return True


def test_invalid_threshold_warn_some_gte_crit_some():
    """Test that warn-some >= crit-some is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--warn-some', '25.0', '--crit-some', '25.0']
    )

    assert return_code == 2, f"Equal some thresholds should exit with 2, got {return_code}"
    assert 'warn-some' in stderr.lower() or 'crit-some' in stderr.lower(), \
        "Should mention threshold in error"

    print("PASS: Invalid threshold (warn-some >= crit-some) test passed")
    return True


def test_invalid_threshold_warn_full_gte_crit_full():
    """Test that warn-full >= crit-full is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--warn-full', '10.0', '--crit-full', '10.0']
    )

    assert return_code == 2, f"Equal full thresholds should exit with 2, got {return_code}"
    assert 'warn-full' in stderr.lower() or 'crit-full' in stderr.lower(), \
        "Should mention threshold in error"

    print("PASS: Invalid threshold (warn-full >= crit-full) test passed")
    return True


def test_resource_flag():
    """Test that --resource flag is recognized."""
    resources = ['cpu', 'memory', 'io', 'all']

    for resource in resources:
        return_code, stdout, stderr = run_command(
            ['./baremetal_proc_pressure_monitor.py', '--resource', resource]
        )

        assert return_code in [0, 1, 2], f"Resource {resource} should be valid, got {return_code}"
        assert 'invalid choice' not in stderr.lower(), f"Resource {resource} should be a valid choice"

    print("PASS: Resource flag test passed")
    return True


def test_short_resource_flag():
    """Test that -r shorthand for --resource works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '-r', 'cpu']
    )

    assert return_code in [0, 1, 2], f"Short resource flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-r should be recognized"

    print("PASS: Short resource flag test passed")
    return True


def test_invalid_resource_rejected():
    """Test that invalid resource values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--resource', 'invalid']
    )

    assert return_code == 2, f"Invalid resource should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should show error for invalid resource"

    print("PASS: Invalid resource rejection test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--warn-only']
    )

    assert return_code in [0, 1, 2], f"Warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '-w']
    )

    assert return_code in [0, 1, 2], f"Short warn-only flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--verbose']
    )

    assert return_code in [0, 1, 2], f"Verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '-v']
    )

    assert return_code in [0, 1, 2], f"Short verbose flag should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags can be combined."""
    return_code, stdout, stderr = run_command([
        './baremetal_proc_pressure_monitor.py',
        '--format', 'table',
        '--warn-some', '5.0',
        '--crit-some', '20.0',
        '--resource', 'memory',
        '--verbose'
    ])

    assert return_code in [0, 1, 2], f"Combined flags should work, got {return_code}"
    assert 'unrecognized arguments' not in stderr.lower(), "Combined flags should be recognized"

    print("PASS: Combined flags test passed")
    return True


def test_json_output_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1, 2], f"JSON format should work, got {return_code}"

    try:
        data = json.loads(stdout)
        assert isinstance(data, dict), "JSON output should be a dictionary"

        # Verify required fields
        required_fields = ['timestamp', 'psi_available', 'healthy']
        for field in required_fields:
            assert field in data, f"JSON should contain '{field}' field"

        # If PSI is available, check for metrics structure
        if data['psi_available']:
            assert 'metrics' in data, "Should have metrics when PSI available"
            assert 'status' in data, "Should have status when PSI available"
            assert 'issues' in data, "Should have issues list"
            assert 'warnings' in data, "Should have warnings list"

            # Verify types
            assert isinstance(data['issues'], list), "issues should be a list"
            assert isinstance(data['warnings'], list), "warnings should be a list"
            assert isinstance(data['healthy'], bool), "healthy should be a boolean"
        else:
            # PSI not available case
            assert 'error' in data, "Should have error when PSI not available"

    except json.JSONDecodeError as e:
        raise AssertionError(f"JSON output is invalid: {e}\nOutput: {stdout[:200]}")

    print("PASS: JSON output structure test passed")
    return True


def test_json_output_when_psi_available():
    """Test JSON output structure when PSI is available."""
    # Check if PSI is available on this system
    psi_available = os.path.exists('/proc/pressure/cpu')

    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--format', 'json']
    )

    data = json.loads(stdout)

    if psi_available:
        assert data['psi_available'] is True, "Should report PSI as available"
        assert 'metrics' in data, "Should have metrics"

        # Check for expected resource metrics
        metrics = data['metrics']
        for resource in ['cpu', 'memory', 'io']:
            if resource in metrics and 'error' not in metrics[resource]:
                if 'some' in metrics[resource]:
                    some = metrics[resource]['some']
                    assert 'avg10' in some, f"{resource} should have avg10"
                    assert 'avg60' in some, f"{resource} should have avg60"
                    assert 'avg300' in some, f"{resource} should have avg300"

                    # Values should be non-negative
                    assert some['avg10'] >= 0, "avg10 should be non-negative"
                    assert some['avg60'] >= 0, "avg60 should be non-negative"
                    assert some['avg300'] >= 0, "avg300 should be non-negative"
    else:
        assert data['psi_available'] is False, "Should report PSI as unavailable"

    print("PASS: JSON output PSI availability test passed")
    return True


def test_plain_output_contains_expected_info():
    """Test that plain output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--format', 'plain']
    )

    assert return_code in [0, 1, 2], f"Plain format should work, got {return_code}"

    # Check for output content (either PSI data or unavailable message)
    output = stdout + stderr
    assert ('pressure' in output.lower() or 'psi' in output.lower()), \
        "Output should mention pressure or PSI"

    print("PASS: Plain output content test passed")
    return True


def test_table_output_contains_expected_info():
    """Test that table output contains expected information."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--format', 'table']
    )

    assert return_code in [0, 1, 2], f"Table format should work, got {return_code}"

    # If PSI is available, check for table formatting
    if return_code in [0, 1]:
        assert '+' in stdout or '|' in stdout, "Table output should have table formatting"

    print("PASS: Table output content test passed")
    return True


def test_script_is_executable():
    """Test that the script has executable permissions."""
    script_path = './baremetal_proc_pressure_monitor.py'
    st = os.stat(script_path)
    is_executable = bool(st.st_mode & stat.S_IXUSR)

    assert is_executable, f"{script_path} should be executable"

    print("PASS: Script executable test passed")
    return True


def test_shebang_present():
    """Test that script has proper shebang."""
    with open('./baremetal_proc_pressure_monitor.py', 'r') as f:
        first_line = f.readline()

    assert first_line.startswith('#!/usr/bin/env python3'), \
        "Script should have proper python3 shebang"

    print("PASS: Shebang test passed")
    return True


def test_docstring_present():
    """Test that script has a module docstring."""
    with open('./baremetal_proc_pressure_monitor.py', 'r') as f:
        content = f.read()

    assert '"""' in content, "Script should have docstring"
    assert 'Exit codes:' in content, "Docstring should document exit codes"
    assert 'pressure' in content.lower(), "Docstring should mention pressure"
    assert 'psi' in content.lower(), "Docstring should mention PSI"

    print("PASS: Docstring test passed")
    return True


def test_exit_code_documentation():
    """Test that exit codes are properly documented."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--help']
    )

    assert '0' in stdout, "Help should document exit code 0"
    assert '1' in stdout, "Help should document exit code 1"
    assert '2' in stdout, "Help should document exit code 2"

    print("PASS: Exit code documentation test passed")
    return True


def test_status_value_valid():
    """Test that status value in JSON output is valid."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--format', 'json']
    )

    assert return_code in [0, 1, 2], f"Should run successfully, got {return_code}"

    data = json.loads(stdout)

    if data['psi_available']:
        valid_statuses = ['healthy', 'warning', 'critical']
        assert data['status'] in valid_statuses, \
            f"Status should be one of {valid_statuses}, got {data['status']}"

    print("PASS: Status value validation test passed")
    return True


def test_high_thresholds_no_warnings():
    """Test that very high thresholds produce no warnings on typical systems."""
    return_code, stdout, stderr = run_command([
        './baremetal_proc_pressure_monitor.py',
        '--format', 'json',
        '--warn-some', '90',
        '--crit-some', '95',
        '--warn-full', '90',
        '--crit-full', '95'
    ])

    # If PSI is available and we got a result
    if return_code in [0, 1]:
        data = json.loads(stdout)
        if data['psi_available']:
            assert data['healthy'] is True, "Should be healthy with very high thresholds"
            assert len(data['issues']) == 0, "Should have no issues with very high thresholds"
            assert return_code == 0, "Exit code should be 0 with no issues"

    print("PASS: High threshold no warnings test passed")
    return True


def test_graceful_psi_unavailable():
    """Test graceful handling when PSI files don't exist."""
    # This test verifies the script handles missing PSI gracefully
    # On systems without PSI, it should exit with code 2 and provide helpful message
    return_code, stdout, stderr = run_command(
        ['./baremetal_proc_pressure_monitor.py', '--format', 'json']
    )

    data = json.loads(stdout)

    # Should always have these fields regardless of PSI availability
    assert 'psi_available' in data, "Should indicate PSI availability"
    assert 'timestamp' in data, "Should have timestamp"
    assert 'healthy' in data, "Should have healthy field"

    if not data['psi_available']:
        assert return_code == 2, "Should exit with 2 when PSI unavailable"
        assert 'error' in data, "Should have error message when PSI unavailable"

    print("PASS: Graceful PSI unavailable test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_invalid_format_rejected,
        test_warn_some_threshold_flag,
        test_crit_some_threshold_flag,
        test_warn_full_threshold_flag,
        test_crit_full_threshold_flag,
        test_invalid_threshold_warn_some_gte_crit_some,
        test_invalid_threshold_warn_full_gte_crit_full,
        test_resource_flag,
        test_short_resource_flag,
        test_invalid_resource_rejected,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_combined_flags,
        test_json_output_structure,
        test_json_output_when_psi_available,
        test_plain_output_contains_expected_info,
        test_table_output_contains_expected_info,
        test_script_is_executable,
        test_shebang_present,
        test_docstring_present,
        test_exit_code_documentation,
        test_status_value_valid,
        test_high_thresholds_no_warnings,
        test_graceful_psi_unavailable,
    ]

    print(f"Running {len(tests)} tests for baremetal_proc_pressure_monitor.py...")
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
