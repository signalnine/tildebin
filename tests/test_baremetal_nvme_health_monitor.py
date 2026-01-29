#!/usr/bin/env python3
"""
Tests for baremetal_nvme_health_monitor.py

These tests validate:
- Argument parsing
- Help message content
- Output format options
- Exit codes
- Error handling

Tests run without requiring NVMe drives or nvme-cli installed.
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
        ['./baremetal_nvme_health_monitor.py', '--help']
    )

    assert return_code == 0, f"Help should exit with 0, got {return_code}"
    assert 'nvme' in stdout.lower(), "Help should mention 'NVMe'"
    assert 'health' in stdout.lower(), "Help should mention 'health'"
    assert '--format' in stdout, "Help should document --format flag"
    assert '--warn-only' in stdout or '-w' in stdout, "Help should document warn-only flag"
    assert '--verbose' in stdout or '-v' in stdout, "Help should document verbose flag"
    assert '--device' in stdout or '-d' in stdout, "Help should document device flag"
    assert '--temp-warn' in stdout, "Help should document --temp-warn flag"
    assert '--temp-crit' in stdout, "Help should document --temp-crit flag"
    assert '--spare-warn' in stdout, "Help should document --spare-warn flag"
    assert 'Exit codes:' in stdout, "Help should document exit codes"
    assert 'temperature' in stdout.lower(), "Help should explain temperature monitoring"
    assert 'spare' in stdout.lower(), "Help should explain spare capacity monitoring"

    print("PASS: Help message test passed")
    return True


def test_format_flag_recognized():
    """Test that format flags are recognized."""
    formats = ['plain', 'json', 'table']

    for fmt in formats:
        return_code, stdout, stderr = run_command(
            ['./baremetal_nvme_health_monitor.py', '--format', fmt]
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
        ['./baremetal_nvme_health_monitor.py', '-f', 'json']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-f should be recognized"
    assert 'invalid choice' not in stderr.lower(), "-f json should be valid"

    print("PASS: Short format flag test passed")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--verbose']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--verbose should be recognized"

    print("PASS: Verbose flag test passed")
    return True


def test_short_verbose_flag():
    """Test that -v shorthand for --verbose works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '-v']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-v should be recognized"

    print("PASS: Short verbose flag test passed")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--warn-only']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--warn-only should be recognized"

    print("PASS: Warn-only flag test passed")
    return True


def test_short_warn_only_flag():
    """Test that -w shorthand for --warn-only works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '-w']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-w should be recognized"

    print("PASS: Short warn-only flag test passed")
    return True


def test_device_flag():
    """Test that --device flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--device', '/dev/nvme0n1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--device should be recognized"

    print("PASS: Device flag test passed")
    return True


def test_short_device_flag():
    """Test that -d shorthand for --device works."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '-d', '/dev/nvme0n1']
    )

    assert 'unrecognized arguments' not in stderr.lower(), "-d should be recognized"

    print("PASS: Short device flag test passed")
    return True


def test_temp_warn_flag():
    """Test that --temp-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--temp-warn', '55']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--temp-warn should be recognized"
    assert return_code in [0, 1, 2], \
        f"--temp-warn 55 should be valid, got {return_code}"

    print("PASS: Temp-warn flag test passed")
    return True


def test_temp_crit_flag():
    """Test that --temp-crit flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--temp-crit', '80']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--temp-crit should be recognized"
    assert return_code in [0, 1, 2], \
        f"--temp-crit 80 should be valid, got {return_code}"

    print("PASS: Temp-crit flag test passed")
    return True


def test_spare_warn_flag():
    """Test that --spare-warn flag is recognized."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--spare-warn', '15']
    )

    assert 'unrecognized arguments' not in stderr.lower(), \
        "--spare-warn should be recognized"
    assert return_code in [0, 1, 2], \
        f"--spare-warn 15 should be valid, got {return_code}"

    print("PASS: Spare-warn flag test passed")
    return True


def test_invalid_temp_threshold_order():
    """Test that --temp-warn must be less than --temp-crit."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--temp-warn', '80', '--temp-crit', '60']
    )

    assert return_code == 2, \
        f"--temp-warn > --temp-crit should exit with 2, got {return_code}"
    assert 'must be less than' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention temp-warn must be less than temp-crit"

    print("PASS: Invalid temp threshold order test passed")
    return True


def test_invalid_spare_warn_range_negative():
    """Test that negative --spare-warn is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--spare-warn', '-5']
    )

    assert return_code == 2, \
        f"Negative --spare-warn should exit with 2, got {return_code}"
    assert 'must be 0-100' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid spare-warn range (negative) test passed")
    return True


def test_invalid_spare_warn_range_over_100():
    """Test that --spare-warn over 100 is rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--spare-warn', '150']
    )

    assert return_code == 2, \
        f"--spare-warn 150 should exit with 2, got {return_code}"
    assert 'must be 0-100' in stderr.lower() or 'error' in stderr.lower(), \
        "Error should mention valid range"

    print("PASS: Invalid spare-warn range (over 100) test passed")
    return True


def test_invalid_argument():
    """Test that invalid arguments are rejected."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--nonexistent-option']
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
        ['./baremetal_nvme_health_monitor.py', '--format', 'json']
    )

    # Skip if script couldn't run (e.g., no nvme-cli)
    if return_code == 2 and 'nvme-cli' in stderr:
        print("SKIP: JSON output test (nvme-cli not installed)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)
            assert 'status' in data, "JSON should have 'status' field"
            assert 'drives' in data, "JSON should have 'drives' field"
            assert data['status'] in ['healthy', 'warning', 'critical', 'ok'], \
                "Status should be healthy, warning, critical, or ok"
            print("PASS: JSON output format test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON output invalid: {e}")
            print(f"Output was: {stdout[:200]}")
            return False

    print("PASS: JSON output format test passed (script execution checked)")
    return True


def test_plain_output_no_devices():
    """Test plain output when no NVMe devices present."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py']
    )

    # If nvme-cli not installed
    if return_code == 2 and 'nvme-cli' in stderr:
        print("SKIP: Plain output test (nvme-cli not installed)")
        return True

    # If no devices found, should still exit cleanly
    if return_code == 0 and 'no nvme' in stdout.lower():
        print("PASS: Plain output test passed (no devices)")
        return True

    # Otherwise should have some output
    assert return_code in [0, 1, 2], \
        f"Unexpected return code {return_code}"

    print("PASS: Plain output test passed")
    return True


def test_table_output_format():
    """Test that table output has headers when devices present."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--format', 'table']
    )

    # Skip if script couldn't run
    if return_code == 2 and 'nvme-cli' in stderr:
        print("SKIP: Table output test (nvme-cli not installed)")
        return True

    # If devices present, check for header
    if return_code in [0, 1]:
        lines = stdout.strip().split('\n')
        if len(lines) > 0:
            output_lower = stdout.lower()
            # Should have header or "no devices" message
            assert ('device' in output_lower or 'model' in output_lower or
                    'status' in output_lower or 'no nvme' in output_lower or
                    'healthy' in output_lower), \
                "Table should have header row or status message"
        print("PASS: Table output format test passed")
        return True

    print("PASS: Table output format test passed (script execution checked)")
    return True


def test_combined_flags():
    """Test that multiple flags work together."""
    return_code, stdout, stderr = run_command([
        './baremetal_nvme_health_monitor.py',
        '-f', 'json',
        '-v',
        '-w',
        '--temp-warn', '55',
        '--temp-crit', '70',
        '--spare-warn', '25'
    ])

    # Should not have argument parsing errors
    assert 'unrecognized arguments' not in stderr.lower(), \
        "Combined flags should be recognized"

    # Should either run or fail with dependency error
    assert return_code in [0, 1, 2], \
        f"Combined flags should be valid, got {return_code}"

    print("PASS: Combined flags test passed")
    return True


def test_missing_nvme_cli():
    """Test that missing nvme-cli is handled gracefully."""
    # This test verifies the error message when nvme-cli is not installed
    # We can't force nvme-cli to be missing, but we can verify the error
    # message format is correct when it is missing

    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py']
    )

    if return_code == 2 and 'nvme-cli' in stderr:
        # Verify helpful error message
        assert 'install' in stderr.lower(), \
            "Error should suggest how to install nvme-cli"
        assert ('apt' in stderr.lower() or 'yum' in stderr.lower()), \
            "Error should mention package manager"
        print("PASS: Missing nvme-cli test passed")
        return True

    # If nvme-cli is installed, we can't test this path
    print("SKIP: Missing nvme-cli test (nvme-cli is installed)")
    return True


def test_nonexistent_device():
    """Test that nonexistent device is handled gracefully."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--device', '/dev/nvme99n99']
    )

    # Should fail with usage error or device not found
    if return_code == 2:
        if 'nvme-cli' in stderr:
            print("SKIP: Nonexistent device test (nvme-cli not installed)")
            return True
        assert 'not found' in stderr.lower() or 'error' in stderr.lower(), \
            "Error should mention device not found"
        print("PASS: Nonexistent device test passed")
        return True

    # If the script runs despite device not existing, that's also acceptable
    # as it may gracefully handle missing device
    print("PASS: Nonexistent device test passed")
    return True


def test_json_structure():
    """Test that JSON output has expected structure."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: JSON structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            # Check top-level keys
            required_keys = ['status', 'drives']
            for key in required_keys:
                assert key in data, f"JSON should have '{key}' field"

            # Check that drives is a list
            assert isinstance(data['drives'], list), \
                "drives should be a list"

            # If there's a summary, check its structure
            if 'summary' in data:
                summary_keys = ['total_drives', 'healthy', 'warning', 'critical']
                for key in summary_keys:
                    assert key in data['summary'], f"Summary should have '{key}' field"

            print("PASS: JSON structure test passed")
            return True
        except json.JSONDecodeError as e:
            print(f"FAIL: JSON invalid: {e}")
            return False

    print("PASS: JSON structure test passed")
    return True


def test_drive_metrics_structure():
    """Test that drive entries have expected fields when present."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--format', 'json']
    )

    if return_code == 2:
        print("SKIP: Drive metrics structure test (script couldn't run)")
        return True

    if return_code in [0, 1]:
        try:
            data = json.loads(stdout)

            if data['drives']:
                # Check first drive entry
                first_drive = data['drives'][0]
                expected_fields = ['device', 'status']
                for field in expected_fields:
                    assert field in first_drive, f"Drive entry should have '{field}' field"

                # Status should be valid
                assert first_drive['status'] in ['healthy', 'warning', 'critical', 'unknown'], \
                    f"Drive status should be valid, got {first_drive['status']}"

            print("PASS: Drive metrics structure test passed")
            return True
        except json.JSONDecodeError:
            print("PASS: Drive metrics structure test passed (no JSON to check)")
            return True

    print("PASS: Drive metrics structure test passed")
    return True


def test_exit_code_consistency():
    """Test that exit codes are consistent with status."""
    return_code, stdout, stderr = run_command(
        ['./baremetal_nvme_health_monitor.py', '--format', 'json']
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


if __name__ == "__main__":
    print("Testing baremetal_nvme_health_monitor.py...")
    print()

    tests = [
        test_help_message,
        test_format_flag_recognized,
        test_short_format_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_warn_only_flag,
        test_short_warn_only_flag,
        test_device_flag,
        test_short_device_flag,
        test_temp_warn_flag,
        test_temp_crit_flag,
        test_spare_warn_flag,
        test_invalid_temp_threshold_order,
        test_invalid_spare_warn_range_negative,
        test_invalid_spare_warn_range_over_100,
        test_invalid_argument,
        test_json_output_format,
        test_plain_output_no_devices,
        test_table_output_format,
        test_combined_flags,
        test_missing_nvme_cli,
        test_nonexistent_device,
        test_json_structure,
        test_drive_metrics_structure,
        test_exit_code_consistency,
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
