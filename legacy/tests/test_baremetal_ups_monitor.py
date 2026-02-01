#!/usr/bin/env python3
"""
Tests for baremetal_ups_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual UPS hardware or monitoring software.
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
        'baremetal_ups_monitor.py',
        '--help'
    ])

    if return_code != 0:
        print(f"[FAIL] Help message test: Expected return code 0, got {return_code}")
        return False

    if 'Uninterruptible Power Supply' not in stdout:
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
            'baremetal_ups_monitor.py',
            '--format', fmt
        ])

        # Script should run (may exit with 2 if tools not available, which is OK)
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
        'baremetal_ups_monitor.py',
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
        'baremetal_ups_monitor.py',
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


def test_combined_options():
    """Test that multiple options can be used together."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ups_monitor.py',
        '--format', 'json',
        '--warn-only',
        '--verbose'
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
        'baremetal_ups_monitor.py',
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


def test_no_ups_tools_handling():
    """Test graceful handling when UPS tools are not available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ups_monitor.py'
    ])

    # Should either work (0, 1) or report missing tools (2)
    if return_code not in [0, 1, 2]:
        print(f"[FAIL] No UPS tools handling test: Unexpected return code {return_code}")
        return False

    # If tools not found, should have helpful error message
    if return_code == 2:
        if 'No UPS monitoring tools found' not in stderr and 'No UPS devices found' not in stdout:
            # Tools might be installed but no UPS connected - that's OK too
            pass
        else:
            if 'apt-get' not in stderr.lower() and 'yum' not in stderr.lower():
                print("[FAIL] No UPS tools handling test: Missing helpful installation message")
                return False

    print("[PASS] No UPS tools handling test")
    return True


def test_short_flags():
    """Test that short flag versions work."""
    # Test -f for --format
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ups_monitor.py',
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
        'baremetal_ups_monitor.py',
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
        'baremetal_ups_monitor.py',
        '-v'
    ])

    if return_code not in [0, 1, 2]:
        print(f"[FAIL] Short flags test (-v): Unexpected return code {return_code}")
        return False

    if 'unrecognized arguments' in stderr.lower():
        print("[FAIL] Short flags test (-v): Flag not recognized")
        return False

    print("[PASS] Short flags test")
    return True


def test_exit_codes_documented():
    """Test that exit codes are documented in help."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ups_monitor.py',
        '--help'
    ])

    if 'Exit codes:' not in stdout:
        print("[FAIL] Exit codes documented test: Exit codes section not found")
        return False

    if '0 -' not in stdout or '1 -' not in stdout or '2 -' not in stdout:
        print("[FAIL] Exit codes documented test: Exit code descriptions not found")
        return False

    print("[PASS] Exit codes documented test")
    return True


def test_json_output_structure():
    """Test that JSON output has expected structure when tools available."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ups_monitor.py',
        '--format', 'json'
    ])

    # If tools not available, skip JSON structure check
    if return_code == 2:
        print("[PASS] JSON output structure test (skipped - no UPS tools)")
        return True

    import json
    try:
        data = json.loads(stdout)

        # Check expected keys exist
        if 'ups_units' not in data:
            print("[FAIL] JSON output structure test: Missing key 'ups_units'")
            return False

        if 'summary' not in data:
            print("[FAIL] JSON output structure test: Missing key 'summary'")
            return False

        # Check summary has expected structure
        summary_keys = ['total_ups', 'critical', 'warning', 'ok']
        for key in summary_keys:
            if key not in data['summary']:
                print(f"[FAIL] JSON output structure test: Missing summary key '{key}'")
                return False

        print("[PASS] JSON output structure test")
        return True

    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON output structure test: Invalid JSON - {e}")
        return False


def test_supported_software_documented():
    """Test that supported UPS software is documented in help."""
    return_code, stdout, stderr = run_command([
        sys.executable,
        'baremetal_ups_monitor.py',
        '--help'
    ])

    if 'NUT' not in stdout and 'upsc' not in stdout:
        print("[FAIL] Supported software test: NUT not mentioned")
        return False

    if 'apcaccess' not in stdout and 'APC' not in stdout:
        print("[FAIL] Supported software test: APC not mentioned")
        return False

    print("[PASS] Supported software documented test")
    return True


def main():
    """Run all tests."""
    # Change to script directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(script_dir)

    print("Running baremetal_ups_monitor.py tests...")
    print()

    tests = [
        test_help_message,
        test_format_options,
        test_warn_only_flag,
        test_verbose_flag,
        test_combined_options,
        test_invalid_format,
        test_no_ups_tools_handling,
        test_short_flags,
        test_exit_codes_documented,
        test_json_output_structure,
        test_supported_software_documented,
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
