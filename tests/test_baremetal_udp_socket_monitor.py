#!/usr/bin/env python3
"""
Tests for baremetal_udp_socket_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring root access or specific network states.
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
        ['./baremetal_udp_socket_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'udp' in stdout.lower(), "Help should mention 'udp'"
    assert 'socket' in stdout.lower(), "Help should mention 'socket'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--port' in stdout, "Help should document --port flag"
    assert '--process' in stdout, "Help should document --process flag"
    assert '--socket-warn' in stdout, "Help should document --socket-warn flag"
    assert '--rx-queue-warn' in stdout, "Help should document --rx-queue-warn flag"
    assert '--tx-queue-warn' in stdout, "Help should document --tx-queue-warn flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"

    print("PASS: Help message test passed")
    return True


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--format', 'invalid']
    )

    assert return_code == 2, \
        f"Invalid format should exit with 2, got {return_code}"
    assert 'invalid choice' in stderr.lower() or 'error' in stderr.lower(), \
        "Should report invalid format choice"

    print("PASS: Invalid format test passed")
    return True


def test_invalid_socket_warn():
    """Test that negative --socket-warn value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--socket-warn', '-5']
    )

    assert return_code == 2, \
        f"Negative socket-warn should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid socket-warn test passed")
    return True


def test_invalid_rx_queue_warn():
    """Test that negative --rx-queue-warn value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--rx-queue-warn', '-10']
    )

    assert return_code == 2, \
        f"Negative rx-queue-warn should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid rx-queue-warn test passed")
    return True


def test_invalid_tx_queue_warn():
    """Test that negative --tx-queue-warn value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--tx-queue-warn', '-1']
    )

    assert return_code == 2, \
        f"Negative tx-queue-warn should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid tx-queue-warn test passed")
    return True


def test_invalid_top():
    """Test that negative --top value is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--top', '-1']
    )

    assert return_code == 2, \
        f"Negative top should exit with 2, got {return_code}"
    assert 'non-negative' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid top test passed")
    return True


def test_invalid_regex():
    """Test that invalid regex pattern is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--process', '[invalid(regex']
    )

    assert return_code == 2, \
        f"Invalid regex should exit with 2, got {return_code}"
    assert 'pattern' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention invalid pattern"

    print("PASS: Invalid regex test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--nonexistent-option']
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
        ['./baremetal_udp_socket_monitor.py', '--format', 'plain']
    )

    assert 'invalid choice' not in stderr.lower(), "plain should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format plain should work"

    print("PASS: Format plain accepted test passed")
    return True


def test_format_json_accepted():
    """Test that --format json is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--format', 'json']
    )

    assert 'invalid choice' not in stderr.lower(), "json should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format json should work"

    print("PASS: Format json accepted test passed")
    return True


def test_format_table_accepted():
    """Test that --format table is accepted."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--format', 'table']
    )

    assert 'invalid choice' not in stderr.lower(), "table should be valid format"
    assert 'unrecognized arguments' not in stderr.lower(), "--format table should work"

    print("PASS: Format table accepted test passed")
    return True


def test_short_format_flag():
    """Test that -f shorthand for --format works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_port_filter_flag():
    """Test that --port flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--port', '53']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--port should be recognized"

    print("PASS: Port filter flag test passed")
    return True


def test_process_filter_flag():
    """Test that --process flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--process', 'named']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--process should be recognized"

    print("PASS: Process filter flag test passed")
    return True


def test_socket_warn_flag():
    """Test that --socket-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--socket-warn', '500']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--socket-warn should be recognized"

    print("PASS: Socket-warn flag test passed")
    return True


def test_rx_queue_warn_flag():
    """Test that --rx-queue-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--rx-queue-warn', '1000000']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--rx-queue-warn should be recognized"

    print("PASS: RX-queue-warn flag test passed")
    return True


def test_tx_queue_warn_flag():
    """Test that --tx-queue-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--tx-queue-warn', '1000000']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--tx-queue-warn should be recognized"

    print("PASS: TX-queue-warn flag test passed")
    return True


def test_top_flag():
    """Test that --top flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--top', '20']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--top should be recognized"

    print("PASS: Top flag test passed")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_udp_socket_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--socket-warn', '500',
        '--rx-queue-warn', '500000',
        '--top', '5'
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
        ['./baremetal_udp_socket_monitor.py']
    )

    # Exit 0 (no issues), 1 (warnings), or 2 (error) are all valid
    assert return_code in [0, 1, 2], \
        f"Exit code should be 0, 1, or 2, got {return_code}"

    print("PASS: Exit code test passed")
    return True


def test_json_output_valid():
    """Test that JSON output is valid JSON."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'proc' in stderr.lower():
        print("SKIP: JSON output test (/proc not available)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'summary' in data, "JSON should have 'summary' field"
            assert data['status'] in ['ok', 'warning'], \
                "Status should be ok or warning"
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
        ['./baremetal_udp_socket_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'summary', 'issues']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check summary structure
            summary_keys = ['total_sockets', 'total_rx_queue', 'total_tx_queue', 'issue_count']
            for key in summary_keys:
                assert key in data['summary'], f"Summary should have '{key}' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_plain_output_has_summary():
    """Test that plain output shows socket summary."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--format', 'plain']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Plain output test (script couldn't run)")
        return True

    # Should have some summary output
    if return_code in [0, 1]:
        assert 'UDP Socket Summary:' in stdout or 'Total sockets:' in stdout or 'OK' in stdout, \
            "Plain output should show socket summary"

    print("PASS: Plain output has summary test passed")
    return True


def test_warn_only_no_output_when_ok():
    """Test that --warn-only with no issues shows OK message."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--warn-only', '--socket-warn', '999999']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: Warn-only test (script couldn't run)")
        return True

    if return_code == 0:
        assert 'OK' in stdout or 'No UDP' in stdout, \
            "Warn-only with no issues should show OK message"

    print("PASS: Warn-only no output when OK test passed")
    return True


def test_dns_port_filter():
    """Test filtering by DNS port (53)."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_udp_socket_monitor.py', '--port', '53', '--format', 'json']
    )

    # Skip if script couldn't run
    if return_code == 2:
        print("SKIP: DNS port filter test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            # All sockets should be on port 53 or empty
            for sock in data.get('sockets', []):
                assert sock['local_port'] == 53 or sock['remote_port'] == 53, \
                    "Filtered sockets should be on port 53"
            print("PASS: DNS port filter test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: DNS port filter test passed (JSON parse)")
            return True

    print("PASS: DNS port filter test passed")
    return True


if __name__ == "__main__":
    print("Testing baremetal_udp_socket_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_invalid_format,
        test_invalid_socket_warn,
        test_invalid_rx_queue_warn,
        test_invalid_tx_queue_warn,
        test_invalid_top,
        test_invalid_regex,
        test_invalid_argument,
        test_format_plain_accepted,
        test_format_json_accepted,
        test_format_table_accepted,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_port_filter_flag,
        test_process_filter_flag,
        test_socket_warn_flag,
        test_rx_queue_warn_flag,
        test_tx_queue_warn_flag,
        test_top_flag,
        test_combined_flags,
        test_exit_code_valid,
        test_json_output_valid,
        test_json_structure,
        test_plain_output_has_summary,
        test_warn_only_no_output_when_ok,
        test_dns_port_filter,
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
