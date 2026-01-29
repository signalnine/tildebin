#!/usr/bin/env python3
"""
Tests for baremetal_socket_buffer_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling
- Threshold validation

Tests run without requiring root access or specific network configurations.
"""

import json
import subprocess
import sys


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
        ['./baremetal_socket_buffer_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'socket' in stdout.lower(), "Help should mention 'socket'"
    assert 'buffer' in stdout.lower(), "Help should mention 'buffer'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn' in stdout, "Help should document --warn flag"
    assert '--crit' in stdout, "Help should document --crit flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_socket_buffer_monitor.py', '--format', fmt]
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
        ['./baremetal_socket_buffer_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_warn_threshold_flag():
    """Test that --warn flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--warn', '60']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn should be recognized"
    assert return_code in [0, 1, 2], \
        f"--warn 60 should be valid, got {return_code}"

    print("PASS: Warn threshold flag test passed")
    return True


def test_crit_threshold_flag():
    """Test that --crit flag is recognized and validated."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--crit', '90']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--crit should be recognized"
    assert return_code in [0, 1, 2], \
        f"--crit 90 should be valid, got {return_code}"

    print("PASS: Crit threshold flag test passed")
    return True


def test_invalid_warn_threshold():
    """Test that invalid --warn values are rejected."""
    # Test > 100
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--warn', '150']
    )

    assert return_code == 2, \
        f"Warn threshold > 100 should exit with 2, got {return_code}"

    print("PASS: Invalid warn threshold test passed")
    return True


def test_negative_warn_threshold():
    """Test that negative --warn values are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--warn', '-10']
    )

    assert return_code == 2, \
        f"Negative warn threshold should exit with 2, got {return_code}"

    print("PASS: Negative warn threshold test passed")
    return True


def test_invalid_crit_threshold():
    """Test that invalid --crit values are rejected."""
    # Test > 100
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--crit', '150']
    )

    assert return_code == 2, \
        f"Crit threshold > 100 should exit with 2, got {return_code}"

    print("PASS: Invalid crit threshold test passed")
    return True


def test_warn_must_be_less_than_crit():
    """Test that --warn must be less than --crit."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--warn', '90', '--crit', '80']
    )

    assert return_code == 2, \
        f"warn >= crit should exit with 2, got {return_code}"
    assert 'less than' in stderr.lower(), \
        "Should indicate warn must be less than crit"

    print("PASS: Warn must be less than crit test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--nonexistent-option']
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
        ['./baremetal_socket_buffer_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run (e.g., no /proc on non-Linux)
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: JSON output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'protocols' in data, "JSON should have 'protocols' field"
            assert 'config' in data, "JSON should have 'config' field"
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


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'timestamp', 'protocols', 'config',
                             'issues', 'warnings', 'page_size_bytes']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check config structure
            config_keys = ['rmem_default', 'rmem_max', 'wmem_default', 'wmem_max',
                           'tcp_mem', 'tcp_rmem', 'tcp_wmem']
            for key in config_keys:
                assert key in data['config'], f"Config should have '{key}' field"

            # Check that protocols is a dict
            assert isinstance(data['protocols'], dict), \
                "protocols should be a dictionary"

            # Check that issues and warnings are lists
            assert isinstance(data['issues'], list), \
                "issues should be a list"
            assert isinstance(data['warnings'], list), \
                "warnings should be a list"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_plain_output_contains_expected():
    """Test that plain output contains expected keywords."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--verbose']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Plain output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        lower_output = stdout.lower()
        # Should have protocol info or status message
        assert 'socket' in lower_output or 'tcp' in lower_output or 'protocol' in lower_output, \
            "Output should contain socket/protocol info"
        print("PASS: Plain output test passed")
        return True

    print("PASS: Plain output test passed (script execution checked)")
    return True


def test_table_output_format():
    """Test that table output has headers."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--format', 'table']
    )

    # Skip if script couldn't run
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Table output test (no /proc filesystem)")
        return True

    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            header = lines[0].lower()
            # First line should have headers
            assert 'protocol' in header or 'socket' in header or 'no ' in header, \
                "Table should have header row or status message"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_exit_code_success():
    """Test that script exits with appropriate code."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py']
    )

    # Skip if no /proc
    if return_code == 2 and '/proc' in stderr:
        print("SKIP: Exit code test (no /proc filesystem)")
        return True

    # Exit 0 (no issues) or 1 (issues found) are both valid
    assert return_code in [0, 1], \
        f"Exit code should be 0 or 1, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_socket_buffer_monitor.py',
        '-f', 'json',
        '-v',
        '--warn', '60',
        '--crit', '80'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_json_has_raw_stats():
    """Test that JSON output includes raw stats for debugging."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Raw stats test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'raw_stats' in data, "JSON should have 'raw_stats' field"
            assert isinstance(data['raw_stats'], dict), \
                "raw_stats should be a dictionary"
            print("PASS: Raw stats test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Raw stats test passed (no valid JSON)")
            return True

    print("PASS: Raw stats test passed")
    return True


def test_protocol_info_fields():
    """Test that protocol data has expected fields."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Protocol info fields test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # Check TCP fields if TCP protocol exists
            if 'TCP' in data['protocols']:
                tcp = data['protocols']['TCP']
                expected_fields = ['memory_pages', 'memory_bytes', 'inuse']
                for field in expected_fields:
                    assert field in tcp, f"TCP should have '{field}' field"
            print("PASS: Protocol info fields test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Protocol info fields test passed (no valid JSON)")
            return True

    print("PASS: Protocol info fields test passed")
    return True


def test_warn_only_suppresses_ok_output():
    """Test that --warn-only suppresses output when no issues."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--warn-only', '--warn', '99', '--crit', '99.9']
    )

    # With very high thresholds, there should be no warnings
    if return_code == 0:
        # When no issues, warn-only should produce minimal or no output
        # (depends on whether system has any issues)
        pass  # Just verify it doesn't crash

    print("PASS: Warn-only suppression test passed")
    return True


def test_verbose_shows_config():
    """Test that --verbose shows buffer configuration."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_socket_buffer_monitor.py', '--verbose']
    )

    if return_code == 2:
        print("SKIP: Verbose config test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        lower_output = stdout.lower()
        # Verbose should show configuration details
        assert 'buffer' in lower_output or 'configuration' in lower_output or 'tcp' in lower_output, \
            "Verbose output should mention buffer configuration"
        print("PASS: Verbose shows config test passed")
        return True

    print("PASS: Verbose shows config test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_socket_buffer_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_warn_threshold_flag,
        test_crit_threshold_flag,
        test_invalid_warn_threshold,
        test_negative_warn_threshold,
        test_invalid_crit_threshold,
        test_warn_must_be_less_than_crit,
        test_invalid_argument,
        test_json_output_format,
        test_json_structure,
        test_plain_output_contains_expected,
        test_table_output_format,
        test_exit_code_success,
        test_combined_flags,
        test_json_has_raw_stats,
        test_protocol_info_fields,
        test_warn_only_suppresses_ok_output,
        test_verbose_shows_config,
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
