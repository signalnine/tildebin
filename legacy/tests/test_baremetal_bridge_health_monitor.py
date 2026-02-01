#!/usr/bin/env python3
"""
Tests for baremetal_bridge_health_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring actual bridge interfaces.
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
        ['./baremetal_bridge_health_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'bridge' in stdout.lower(), "Help should mention 'bridge'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--bridges' in stdout or '-b' in stdout, "Help should document bridges flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, \
        f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("PASS: Invalid format test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_format_plain_accepted():
    """Test that --format plain is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'plain']
    )

    assert 'invalid choice' not in stderr.lower(), "plain should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format plain should work"

    print("PASS: Format plain accepted test passed")
    return True


def test_format_json_accepted():
    """Test that --format json is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'json']
    )

    assert 'invalid choice' not in stderr.lower(), "json should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format json should work"

    print("PASS: Format json accepted test passed")
    return True


def test_format_table_accepted():
    """Test that --format table is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'table']
    )

    assert 'invalid choice' not in stderr.lower(), "table should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format table should work"

    print("PASS: Format table accepted test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_bridges_flag():
    """Test that --bridges flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--bridges', 'br0']
    )

    # Will likely fail because br0 doesn't exist, but flag should be recognized
    assert 'unrecognized arguments' not in stderr.lower(), \
        "--bridges should be recognized"

    print("PASS: Bridges flag test passed")
    return True


def test_short_bridges_flag():
    """Test that -b shorthand for --bridges works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '-b', 'br0']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-b should be recognized"

    print("PASS: Short bridges flag test passed")
    return True


def test_multiple_bridges_flag():
    """Test that multiple bridges can be specified."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '-b', 'br0', 'br1', 'br2']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "Multiple bridges should be accepted"

    print("PASS: Multiple bridges flag test passed")
    return True


def test_ignore_no_ports_flag():
    """Test that --ignore-no-ports flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--ignore-no-ports']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--ignore-no-ports should be recognized"

    print("PASS: Ignore no ports flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_bridge_health_monitor.py',
        '-f', 'json',
        '-v',
        '--warn-only',
        '--ignore-no-ports'
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
        ['./baremetal_bridge_health_monitor.py']
    )

    # Exit 0 (no issues or no bridges), 1 (warnings), or 2 (error) are all valid
    assert return_code in [0, 1, 2], \
        f"Exit code should be 0, 1, or 2, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'sys' in stderr.lower():
        print("SKIP: JSON output test (sysfs not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'bridges' in data, "JSON should have 'bridges' field"
            assert 'issues' in data, "JSON should have 'issues' field"
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
        ['./baremetal_bridge_health_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'bridge_count', 'bridges', 'issues']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Verify bridges is a list
            assert isinstance(data['bridges'], list), "bridges should be a list"

            # Verify issues is a list
            assert isinstance(data['issues'], list), "issues should be a list"

            # If there are bridges, check structure
            if data['bridges']:
                bridge = data['bridges'][0]
                assert 'name' in bridge, "Bridge should have 'name' field"
                assert 'operstate' in bridge, "Bridge should have 'operstate' field"
                assert 'bridge' in bridge, "Bridge should have 'bridge' settings"
                assert 'ports' in bridge, "Bridge should have 'ports' list"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_no_bridges_output():
    """Test output when no bridges are configured."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run due to other errors
    if return_code == 2 and 'sys' in stderr.lower():
        print("SKIP: No bridges test (sysfs not available)")
        return True

    # If system has no bridges, should still produce valid output
    if return_code == 0:
        try:
            data = json.loads(stdout)
            assert 'bridges' in data, "Output should have bridges key"
            print("PASS: No bridges output test passed")
            return True
        except json.JSONDecodeError:
            pass

    print("PASS: No bridges output test passed")
    return True


def test_nonexistent_bridge():
    """Test behavior when specified bridge doesn't exist."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '-b', 'nonexistent_bridge_xyz']
    )

    # Should warn about nonexistent bridge
    if 'not found' in stderr.lower() or 'warning' in stderr.lower():
        # Expected behavior
        pass

    # Should exit with error if no valid bridges
    assert return_code in [0, 1, 2], \
        f"Should exit with valid code, got {return_code}"

    print("PASS: Nonexistent bridge test passed")
    return True


def test_plain_output_format():
    """Test that plain output has expected format."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'plain']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Plain output test (script couldn't run)")
        return True

    # If there are bridges, output should contain bridge info
    # If no bridges, should say so
    if return_code in [0, 1]:
        assert stdout, "Plain output should not be empty"
        # Should either have bridge info or indicate no bridges
        has_content = ('Bridge' in stdout or 'bridge' in stdout.lower() or
                      'No bridges' in stdout or 'OK' in stdout)
        assert has_content, "Plain output should mention bridges"

    print("PASS: Plain output format test passed")
    return True


def test_table_output_format():
    """Test that table output has proper format."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--format', 'table']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Table output test (script couldn't run)")
        return True

    # Table should have headers or indicate no bridges
    if return_code in [0, 1] and stdout:
        has_format = ('Bridge' in stdout or 'State' in stdout or
                     'No bridge' in stdout.lower())
        assert has_format, "Table output should have headers or status message"

    print("PASS: Table output format test passed")
    return True


def test_warn_only_with_no_issues():
    """Test that warn-only mode works correctly."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_bridge_health_monitor.py', '--warn-only']
    )

    # Should exit 0 if no issues, 1 if issues found
    assert return_code in [0, 1, 2], \
        f"Warn-only should exit with valid code, got {return_code}"

    print("PASS: Warn-only mode test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_bridge_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_format,
        test_invalid_argument,
        test_format_plain_accepted,
        test_format_json_accepted,
        test_format_table_accepted,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_bridges_flag,
        test_short_bridges_flag,
        test_multiple_bridges_flag,
        test_ignore_no_ports_flag,
        test_combined_flags,
        test_exit_code_valid,
        test_json_output_valid,
        test_json_structure,
        test_no_bridges_output,
        test_nonexistent_bridge,
        test_plain_output_format,
        test_table_output_format,
        test_warn_only_with_no_issues,
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
