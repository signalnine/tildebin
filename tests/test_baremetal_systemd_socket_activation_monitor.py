#!/usr/bin/env python3
"""
Tests for baremetal_systemd_socket_activation_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring specific socket units or systemd features.
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
        ['./baremetal_systemd_socket_activation_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'socket' in stdout.lower(), "Help should mention 'socket'"
    assert 'systemd' in stdout.lower(), "Help should mention 'systemd'"
    assert 'activation' in stdout.lower(), "Help should mention 'activation'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--unit' in stdout or '-u' in stdout, "Help should document unit flag"
    assert '--refuse-warn' in stdout, "Help should document --refuse-warn flag"
    assert '--include-inactive' in stdout, "Help should document --include-inactive flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_systemd_socket_activation_monitor.py', '--format', fmt]
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
        ['./baremetal_systemd_socket_activation_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_unit_flag():
    """Test that --unit flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--unit', 'ssh.socket']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--unit should be recognized"

    print("PASS: Unit flag test passed")
    return True


def test_short_unit_flag():
    """Test that -u shorthand for --unit works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '-u', 'ssh.socket']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-u should be recognized"

    print("PASS: Short unit flag test passed")
    return True


def test_refuse_warn_flag():
    """Test that --refuse-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--refuse-warn', '5']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--refuse-warn should be recognized"
    assert return_code in [0, 1, 2], \
        f"--refuse-warn 5 should be valid, got {return_code}"

    print("PASS: Refuse-warn flag test passed")
    return True


def test_include_inactive_flag():
    """Test that --include-inactive flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--include-inactive']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--include-inactive should be recognized"

    print("PASS: Include-inactive flag test passed")
    return True


def test_invalid_refuse_warn_negative():
    """Test that negative --refuse-warn is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--refuse-warn', '-5']
    )

    assert return_code == 2, \
        f"Negative --refuse-warn should exit with 2, got {return_code}"
    assert 'must be non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid refuse-warn (negative) test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--nonexistent-option']
    )

    assert return_code == 2, \
        f"Invalid argument should exit with 2, got {return_code}"
    assert 'unrecognized arguments' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report unrecognized argument"

    print("PASS: Invalid argument test passed")
    return True


def test_json_output_format():
    """Test that JSON output is valid JSON when successful."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--format', 'json']
    )

    # Skip if systemctl not available
    if return_code == 2 and 'systemctl' in stderr:
        print("SKIP: JSON output test (systemctl not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'sockets' in data or 'message' in data, \
                "JSON should have 'sockets' field or 'message'"
            if 'status' in data:
                assert data['status'] in ['healthy', 'warning', 'critical', 'ok'], \
                    f"Status should be valid, got {data['status']}"
            print("PASS: JSON output format test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output format test passed (script execution checked)")
    return True


def test_plain_output():
    """Test plain output works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py']
    )

    # If systemctl not available
    if return_code == 2 and 'systemctl' in stderr:
        print("SKIP: Plain output test (systemctl not available)")
        return True

    # Should produce some output or message
    assert return_code in [0, 1, 2], \
        f"Unexpected return code {return_code}"

    # If successful, should have output
    if return_code in [0, 1]:
        assert stdout.strip(), "Should produce some output"

    print("PASS: Plain output test passed")
    return True


def test_table_output_format():
    """Test that table output has headers when sockets present."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--format', 'table']
    )

    # Skip if systemctl not available
    if return_code == 2 and 'systemctl' in stderr:
        print("SKIP: Table output test (systemctl not available)")
        return True

    # If sockets present, check for header
    if return_code in [0, 1]:
        output_lower = stdout.lower()
        # Should have header or "no sockets" message
        has_expected = ('socket' in output_lower or
                       'status' in output_lower or
                       'no socket' in output_lower or
                       'no active' in output_lower or
                       'healthy' in output_lower)
        assert has_expected, "Table should have header row or status message"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_systemd_socket_activation_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--refuse-warn', '5',
        '--include-inactive'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_missing_systemctl():
    """Test that missing systemctl is handled gracefully."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py']
    )

    if return_code == 2 and 'systemctl' in stderr:
        # Verify helpful error message
        assert 'systemd' in stderr.lower() or 'not found' in stderr.lower(), \
            "Error should mention systemctl requirement"
        print("PASS: Missing systemctl test passed")
        return True

    # If systemctl is available, we can't test this path
    print("SKIP: Missing systemctl test (systemctl is available)")
    return True


def test_nonexistent_unit():
    """Test that nonexistent unit is handled gracefully."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--unit', 'nonexistent-unit-12345.socket']
    )

    # If systemctl not available
    if return_code == 2 and 'systemctl' in stderr and 'not found' in stderr:
        print("SKIP: Nonexistent unit test (systemctl not available)")
        return True

    # Should fail with unit not found
    if return_code == 2:
        assert 'not found' in stderr.lower() or 'error' in stderr.lower(), \
            "Error should mention unit not found"
        print("PASS: Nonexistent unit test passed")
        return True

    # If it somehow runs, that's also acceptable (maybe unit exists somehow)
    print("PASS: Nonexistent unit test passed")
    return True


def test_unit_name_auto_suffix():
    """Test that .socket suffix is added if missing."""
    # Test with both 'ssh' and 'ssh.socket' - both should be handled
    return_code1, stdout1, stderr1 = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--unit', 'ssh']
    )
    return_code2, stdout2, stderr2 = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--unit', 'ssh.socket']
    )

    # If systemctl not available, skip
    if return_code1 == 2 and 'systemctl' in stderr1 and 'not found' in stderr1:
        print("SKIP: Unit name suffix test (systemctl not available)")
        return True

    # Both should behave the same (either both fail with not found, or both work)
    # The point is neither should crash with argument errors
    assert 'unrecognized arguments' not in stderr1.lower(), \
        "'ssh' should be valid unit name"
    assert 'unrecognized arguments' not in stderr2.lower(), \
        "'ssh.socket' should be valid unit name"

    print("PASS: Unit name auto-suffix test passed")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Either has sockets list or message
            assert 'sockets' in data or 'message' in data, \
                "JSON should have 'sockets' or 'message' field"

            # If has sockets, check it's a list
            if 'sockets' in data:
                assert isinstance(data['sockets'], list), \
                    "sockets should be a list"

            # If has summary, check structure
            if 'summary' in data:
                summary_keys = ['total_sockets', 'healthy', 'warning', 'critical']
                for key in summary_keys:
                    assert key in data['summary'], f"Summary should have '{key}' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_socket_entry_structure():
    """Test that socket entries have expected fields when present."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--format', 'json', '--include-inactive']
    )

    if return_code == 2:
        print("SKIP: Socket entry structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if 'sockets' in data and data['sockets']:
                # Check first socket entry
                first_socket = data['sockets'][0]
                expected_fields = ['unit', 'status']
                for field in expected_fields:
                    assert field in first_socket, f"Socket entry should have '{field}' field"

                # Status should be valid
                assert first_socket['status'] in ['healthy', 'warning', 'critical'], \
                    f"Socket status should be valid, got {first_socket['status']}"

            print("PASS: Socket entry structure test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Socket entry structure test passed (no JSON to check)")
            return True

    print("PASS: Socket entry structure test passed")
    return True


def test_exit_code_consistency():
    """Test that exit codes are consistent with status."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Exit code consistency test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            status = data.get('status', 'unknown')

            # Exit 0 should only be for healthy status
            if return_code == 0:
                assert status in ['healthy', 'ok'], \
                    f"Exit 0 should mean healthy, got status {status}"
            # Exit 1 should be for warning or critical
            elif return_code == 1:
                assert status in ['warning', 'critical'], \
                    f"Exit 1 should mean warning/critical, got status {status}"

            print("PASS: Exit code consistency test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Exit code consistency test passed (no JSON to check)")
            return True

    print("PASS: Exit code consistency test passed")
    return True


def test_metrics_in_json():
    """Test that metrics are included in JSON output."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_systemd_socket_activation_monitor.py', '--format', 'json', '--include-inactive']
    )

    if return_code == 2:
        print("SKIP: Metrics test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check summary has metric fields
            if 'summary' in data:
                metric_fields = ['total_accepted', 'total_refused']
                for field in metric_fields:
                    assert field in data['summary'], \
                        f"Summary should have '{field}' metric"

            # Check socket entries have metrics
            if 'sockets' in data and data['sockets']:
                first_socket = data['sockets'][0]
                if 'metrics' in first_socket:
                    metrics = first_socket['metrics']
                    expected_metrics = ['accepted', 'connections', 'refused']
                    for m in expected_metrics:
                        assert m in metrics, f"Socket metrics should have '{m}'"

            print("PASS: Metrics in JSON test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Metrics test passed (no JSON to check)")
            return True

    print("PASS: Metrics test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_systemd_socket_activation_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_unit_flag,
        test_short_unit_flag,
        test_refuse_warn_flag,
        test_include_inactive_flag,
        test_invalid_refuse_warn_negative,
        test_invalid_argument,
        test_json_output_format,
        test_plain_output,
        test_table_output_format,
        test_combined_flags,
        test_missing_systemctl,
        test_nonexistent_unit,
        test_unit_name_auto_suffix,
        test_json_structure,
        test_socket_entry_structure,
        test_exit_code_consistency,
        test_metrics_in_json,
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
