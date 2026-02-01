#!/usr/bin/env python3
"""
Tests for baremetal_ipmi_sensor_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual IPMI hardware or ipmitool.
"""

import subprocess
import sys
import os


def run_command(cmd):
    """Run a command and return (return_code, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def test_help_message():
    """Test that --help flag works and shows usage information."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--help'
    ])

    if return_code != 0:
        print(f"[FAIL] Help message test: Expected return code 0, got {return_code}")
        return False

    if 'Monitor IPMI sensor readings' not in stdout:
        print("[FAIL] Help message test: Description not found in help output")
        return False

    if '--format' not in stdout:
        print("[FAIL] Help message test: --format option not found")
        return False

    if '--warn-only' not in stdout:
        print("[FAIL] Help message test: --warn-only option not found")
        return False

    if '--verbose' not in stdout:
        print("[FAIL] Help message test: --verbose option not found")
        return False

    if '--type' not in stdout:
        print("[FAIL] Help message test: --type option not found")
        return False

    if '--temp-warn' not in stdout:
        print("[FAIL] Help message test: --temp-warn option not found")
        return False

    if '--temp-crit' not in stdout:
        print("[FAIL] Help message test: --temp-crit option not found")
        return False

    if 'Examples:' not in stdout:
        print("[FAIL] Help message test: Examples section not found")
        return False

    print("[PASS] Help message test")
    return True


def test_format_options():
    """Test that format options are recognized."""
    for fmt in ['plain', 'json', 'table']:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'baremetal_ipmi_sensor_monitor.py',
            '--format', fmt
        ])

        # Script should run (may exit with 2 if ipmitool not available, which is OK)
        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Format option test ({fmt}): Unexpected return code {return_code}")
            return False

        if 'invalid choice' in stderr.lower() or 'unrecognized arguments' in stderr.lower():
            print(f"[FAIL] Format option test ({fmt}): Format not recognized")
            return False

    print("[PASS] Format option test")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--warn-only'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Warn-only flag test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Warn-only flag test: Flag not recognized")
        return False

    print("[PASS] Warn-only flag test")
    return True


def test_verbose_flag():
    """Test that --verbose flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--verbose'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Verbose flag test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Verbose flag test: Flag not recognized")
        return False

    print("[PASS] Verbose flag test")
    return True


def test_type_filter():
    """Test that --type filter is recognized and accepts valid types."""
    valid_types = ['temperature', 'fan', 'voltage', 'power', 'current', 'psu', 'intrusion', 'other']

    for sensor_type in valid_types:
        return_code, stdout, stderr = run_command([
            sys.executable,
            'baremetal_ipmi_sensor_monitor.py',
            '--type', sensor_type
        ])

        if return_code not in [0, 1, 2]:
            print(f"[FAIL] Type filter test ({sensor_type}): Unexpected return code {return_code}")
            return False

        if 'invalid choice' in stderr.lower():
            print(f"[FAIL] Type filter test ({sensor_type}): Type not recognized")
            return False

    print("[PASS] Type filter test")
    return True


def test_multiple_type_filters():
    """Test that multiple --type filters can be specified."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--type', 'temperature',
        '--type', 'fan',
        '--type', 'power'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Multiple type filters test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Multiple type filters test: Multiple types not recognized")
        return False

    print("[PASS] Multiple type filters test")
    return True


def test_invalid_type():
    """Test that invalid type is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--type', 'invalid_type'
    ])

    if return_code != 2:
        print(f"[FAIL] Invalid type test: Expected return code 2, got {return_code}")
        return False

    if 'invalid choice' not in stderr.lower():
        print("[FAIL] Invalid type test: Expected error message about invalid choice")
        return False

    print("[PASS] Invalid type test")
    return True


def test_temperature_thresholds():
    """Test that temperature threshold options are recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--temp-warn', '70',
        '--temp-crit', '80'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Temperature thresholds test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Temperature thresholds test: Options not recognized")
        return False

    print("[PASS] Temperature thresholds test")
    return True


def test_invalid_temperature_threshold():
    """Test that invalid temperature threshold value is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--temp-warn', 'not_a_number'
    ])

    if return_code != 2:
        print(f"[FAIL] Invalid temperature threshold test: Expected return code 2, got {return_code}")
        return False

    if 'invalid' not in stderr.lower():
        print("[FAIL] Invalid temperature threshold test: Expected error message about invalid value")
        return False

    print("[PASS] Invalid temperature threshold test")
    return True


def test_use_sdr_flag():
    """Test that --use-sdr flag is recognized."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--use-sdr'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Use SDR flag test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Use SDR flag test: Flag not recognized")
        return False

    print("[PASS] Use SDR flag test")
    return True


def test_combined_options():
    """Test that multiple options can be used together."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose',
        '--type', 'temperature',
        '--temp-warn', '70',
        '--temp-crit', '80'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Combined options test: Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Combined options test: Options not recognized")
        return False

    print("[PASS] Combined options test")
    return True


def test_invalid_format():
    """Test that invalid format option is rejected."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--format', 'invalid'
    ])

    if return_code != 2:
        print(f"[FAIL] Invalid format test: Expected return code 2, got {return_code}")
        return False

    if 'invalid choice' not in stderr.lower():
        print("[FAIL] Invalid format test: Expected error message about invalid choice")
        return False

    print("[PASS] Invalid format test")
    return True


def test_no_ipmitool_handling():
    """Test graceful handling when ipmitool is not available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py'
    ])

    # Should either work (0, 1) or report missing ipmitool (2)
    if return_code not in [0, 1, 2]:
        print(f"[FAIL] No ipmitool handling test: Unexpected return code {return_code}")
        return False

    # If ipmitool not found, should have helpful error message
    if return_code == 2 and 'ipmitool' in stderr.lower():
        if 'apt-get' not in stderr.lower() and 'yum' not in stderr.lower():
            print("[FAIL] No ipmitool handling test: Missing helpful installation message")
            return False

    print("[PASS] No ipmitool handling test")
    return True


def test_short_flags():
    """Test that short flag versions work."""
    # Test -f for --format
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '-f', 'json'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short flags test (-f): Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Short flags test (-f): Flag not recognized")
        return False

    # Test -w for --warn-only
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '-w'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short flags test (-w): Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Short flags test (-w): Flag not recognized")
        return False

    # Test -v for --verbose
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '-v'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short flags test (-v): Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Short flags test (-v): Flag not recognized")
        return False

    # Test -t for --type
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '-t', 'fan'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short flags test (-t): Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Short flags test (-t): Flag not recognized")
        return False

    print("[PASS] Short flags test")
    return True


def test_exit_code_documentation():
    """Test that exit codes are documented in help."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ipmi_sensor_monitor.py',
        '--help'
    ])

    if return_code != 0:
        print(f"[FAIL] Exit code documentation test: Help failed with code {return_code}")
        return False

    # Check exit codes are documented
    if 'Exit codes:' not in stdout:
        print("[FAIL] Exit code documentation test: Exit codes section not found")
        return False

    print("[PASS] Exit code documentation test")
    return True


def main():
    """Run all tests."""
    # Change to script directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(script_dir)

    print("Running baremetal_ipmi_sensor_monitor.py tests...")
    print()

    tests = [
        test_help_message,
        test_format_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_type_filter,
        test_multiple_type_filters,
        test_invalid_type,
        test_temperature_thresholds,
        test_invalid_temperature_threshold,
        test_use_sdr_flag,
        test_combined_options,
        test_invalid_format,
        test_no_ipmitool_handling,
        test_short_flags,
        test_exit_code_documentation,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: Exception: {e}")
            failed += 1

    print()
    total = passed + failed
    print(f"Test Results: {passed}/{total} tests passed")

    if failed > 0:
        print("Some tests failed!")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
