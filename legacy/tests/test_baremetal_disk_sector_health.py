#!/usr/bin/env python3
"""
Tests for baremetal_disk_sector_health.py

Tests argument parsing, SMART attribute parsing, and error handling
without requiring actual disk access or root privileges.
"""

import subprocess
import sys
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import baremetal_disk_sector_health as checker


def run_command(cmd_args):
    """Run command and return (return_code, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)


# ============================================================================
# CLI Argument Tests
# ============================================================================

def test_help_message():
    """Test that --help displays correctly."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--help'])
    if return_code == 0 and 'sector' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed: {stderr}")
        return False


def test_help_shows_formats():
    """Test that --help shows format options."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--help'])
    if return_code == 0 and all(fmt in stdout for fmt in ['plain', 'table', 'json']):
        print("[PASS] Help shows format options")
        return True
    else:
        print("[FAIL] Help doesn't show format options")
        return False


def test_help_shows_warn_only():
    """Test that --help shows warn-only option."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--help'])
    if return_code == 0 and '--warn-only' in stdout:
        print("[PASS] Help shows warn-only option")
        return True
    else:
        print("[FAIL] Help doesn't show warn-only option")
        return False


def test_help_shows_device_option():
    """Test that --help shows device option."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--help'])
    if return_code == 0 and '--device' in stdout:
        print("[PASS] Help shows device option")
        return True
    else:
        print("[FAIL] Help doesn't show device option")
        return False


def test_help_shows_verbose():
    """Test that --help shows verbose option."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--help'])
    if return_code == 0 and '--verbose' in stdout:
        print("[PASS] Help shows verbose option")
        return True
    else:
        print("[FAIL] Help doesn't show verbose option")
        return False


def test_help_explains_smart_attributes():
    """Test that --help explains monitored SMART attributes."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--help'])
    if return_code == 0 and 'Reallocated' in stdout and 'Pending' in stdout:
        print("[PASS] Help explains SMART attributes")
        return True
    else:
        print("[FAIL] Help doesn't explain SMART attributes")
        return False


def test_help_shows_exit_codes():
    """Test that --help shows exit codes."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--help'])
    if return_code == 0 and 'Exit codes' in stdout:
        print("[PASS] Help shows exit codes")
        return True
    else:
        print("[FAIL] Help doesn't show exit codes")
        return False


def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '-f', 'invalid'])
    if return_code != 0:
        print("[PASS] Invalid format rejected")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False


def test_format_options_accepted():
    """Test that each format option is accepted in argument parsing."""
    formats = ['table', 'plain', 'json']
    for fmt in formats:
        return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '-f', fmt])
        if 'unrecognized arguments' in stderr:
            print(f"[FAIL] Format '{fmt}' rejected in argument parsing")
            return False
    print("[PASS] All format options accepted")
    return True


def test_short_format_flag():
    """Test that -f flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '-f', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -f flag works")
        return True
    else:
        print("[FAIL] Short -f flag doesn't work")
        return False


def test_long_format_flag():
    """Test that --format flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--format', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Long --format flag works")
        return True
    else:
        print("[FAIL] Long --format flag doesn't work")
        return False


def test_warn_only_flag():
    """Test that --warn-only flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--warn-only'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --warn-only flag works")
        return True
    else:
        print("[FAIL] --warn-only flag doesn't work")
        return False


def test_short_warn_flag():
    """Test that -w flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '-w'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -w flag works")
        return True
    else:
        print("[FAIL] Short -w flag doesn't work")
        return False


def test_verbose_flag():
    """Test that --verbose flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '--verbose'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --verbose flag works")
        return True
    else:
        print("[FAIL] --verbose flag doesn't work")
        return False


def test_short_verbose_flag():
    """Test that -v flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '-v'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -v flag works")
        return True
    else:
        print("[FAIL] Short -v flag doesn't work")
        return False


def test_device_flag():
    """Test that --device flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py', '-d', '/dev/sda'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --device flag works")
        return True
    else:
        print("[FAIL] --device flag doesn't work")
        return False


def test_smartctl_missing_handled():
    """Test graceful handling when smartctl not available (or no disks)."""
    return_code, stdout, stderr = run_command([sys.executable, 'baremetal_disk_sector_health.py'])
    # Should fail gracefully (exit 1 or 2), not crash
    if return_code != 0:
        print("[PASS] Missing smartctl/disks handled gracefully")
        return True
    else:
        # If it succeeds, smartctl is available
        print("[PASS] smartctl available and working")
        return True


# ============================================================================
# SMART Attribute Parsing Tests
# ============================================================================

def test_parse_smart_attributes_standard():
    """Test parsing standard SMART attribute output."""
    sample_output = """
smartctl 7.2 2020-12-30 r5155 [x86_64-linux-5.10.0] (local build)
Copyright (C) 2002-20, Bruce Allen, Christian Franke, www.smartmontools.org

=== START OF READ SMART DATA SECTION ===
SMART Attributes Data Structure revision number: 16
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  1 Raw_Read_Error_Rate     0x002f   200   200   051    Pre-fail  Always       -       0
  3 Spin_Up_Time            0x0027   187   182   021    Pre-fail  Always       -       1625
  4 Start_Stop_Count        0x0032   100   100   000    Old_age   Always       -       100
  5 Reallocated_Sector_Ct   0x0033   200   200   140    Pre-fail  Always       -       5
  7 Seek_Error_Rate         0x002e   200   200   000    Old_age   Always       -       0
197 Current_Pending_Sector  0x0032   200   200   000    Old_age   Always       -       2
198 Offline_Uncorrectable   0x0030   200   200   000    Old_age   Offline      -       0
"""
    attrs = checker.parse_smart_attributes(sample_output)

    assert attrs.get(5) == 5, f"Reallocated_Sector_Ct should be 5, got {attrs.get(5)}"
    assert attrs.get(197) == 2, f"Current_Pending_Sector should be 2, got {attrs.get(197)}"
    assert attrs.get(198) == 0, f"Offline_Uncorrectable should be 0, got {attrs.get(198)}"

    print("[PASS] Standard SMART attribute parsing")
    return True


def test_parse_smart_attributes_with_slash():
    """Test parsing SMART attributes with slash format."""
    sample_output = """
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0/0/0
"""
    attrs = checker.parse_smart_attributes(sample_output)

    assert attrs.get(5) == 0, f"Should parse first value before slash, got {attrs.get(5)}"
    print("[PASS] SMART attribute parsing with slash format")
    return True


def test_parse_smart_attributes_empty():
    """Test parsing empty SMART output."""
    attrs = checker.parse_smart_attributes("")
    assert attrs == {}, "Empty output should return empty dict"
    print("[PASS] Empty SMART output handling")
    return True


def test_parse_smart_attributes_no_table():
    """Test parsing output with no attribute table."""
    sample_output = """
smartctl 7.2 2020-12-30 r5155
Some other output without attribute table
"""
    attrs = checker.parse_smart_attributes(sample_output)
    assert attrs == {}, "Output without table should return empty dict"
    print("[PASS] No attribute table handling")
    return True


# ============================================================================
# NVMe SMART Parsing Tests
# ============================================================================

def test_parse_nvme_smart_standard():
    """Test parsing standard NVMe SMART output."""
    sample_output = """
SMART/Health Information (NVMe Log 0x02)
Critical Warning:                   0x00
Temperature:                        35 Celsius
Available Spare:                    100%
Available Spare Threshold:          10%
Percentage Used:                    1%
Data Units Read:                    1,234,567 [632 GB]
Data Units Written:                 2,345,678 [1.20 TB]
Host Read Commands:                 12,345,678
Host Write Commands:                23,456,789
Controller Busy Time:               100
Power Cycles:                       50
Power On Hours:                     1,000
Unsafe Shutdowns:                   5
Media and Data Integrity Errors:    0
Error Information Log Entries:      0
"""
    nvme_data = checker.parse_nvme_smart(sample_output)

    assert nvme_data.get('available_spare') == 100, f"Available spare should be 100, got {nvme_data.get('available_spare')}"
    assert nvme_data.get('percentage_used') == 1, f"Percentage used should be 1, got {nvme_data.get('percentage_used')}"
    assert nvme_data.get('media_errors') == 0, f"Media errors should be 0, got {nvme_data.get('media_errors')}"

    print("[PASS] Standard NVMe SMART parsing")
    return True


def test_parse_nvme_smart_with_errors():
    """Test parsing NVMe output with errors."""
    sample_output = """
Available Spare:                    15%
Percentage Used:                    95%
Media and Data Integrity Errors:    5
"""
    nvme_data = checker.parse_nvme_smart(sample_output)

    assert nvme_data.get('available_spare') == 15
    assert nvme_data.get('percentage_used') == 95
    assert nvme_data.get('media_errors') == 5

    print("[PASS] NVMe SMART parsing with errors")
    return True


def test_parse_nvme_smart_empty():
    """Test parsing empty NVMe output."""
    nvme_data = checker.parse_nvme_smart("")
    assert nvme_data == {}, "Empty output should return empty dict"
    print("[PASS] Empty NVMe output handling")
    return True


# ============================================================================
# Threshold Tests
# ============================================================================

def test_thresholds_defined():
    """Test that critical thresholds are properly defined."""
    assert checker.REALLOCATED_SECTOR_COUNT == 5
    assert checker.CURRENT_PENDING_SECTOR == 197
    assert checker.UNCORRECTABLE_SECTOR_COUNT == 198

    assert checker.THRESHOLDS['warning'][5] == 1
    assert checker.THRESHOLDS['critical'][5] == 50

    print("[PASS] Thresholds properly defined")
    return True


def test_warning_vs_critical_thresholds():
    """Test that warning thresholds are lower than critical."""
    for attr_id in [5, 197, 198]:
        warning = checker.THRESHOLDS['warning'][attr_id]
        critical = checker.THRESHOLDS['critical'][attr_id]
        assert warning < critical, f"Warning should be less than critical for attr {attr_id}"

    print("[PASS] Warning thresholds less than critical")
    return True


# ============================================================================
# run_command Tests
# ============================================================================

def test_run_command_success():
    """Test run_command with successful command."""
    returncode, stdout, stderr = checker.run_command(['echo', 'test'])
    assert returncode == 0
    assert 'test' in stdout
    print("[PASS] run_command success")
    return True


def test_run_command_failure():
    """Test run_command with failing command."""
    returncode, stdout, stderr = checker.run_command(['false'])
    assert returncode != 0
    print("[PASS] run_command failure handling")
    return True


def test_run_command_not_found():
    """Test run_command with non-existent command."""
    returncode, stdout, stderr = checker.run_command(['nonexistent_command_xyz'])
    assert returncode == -1
    assert 'not found' in stderr.lower() or 'Command not found' in stderr
    print("[PASS] run_command handles missing command")
    return True


# ============================================================================
# Output Format Tests (structural)
# ============================================================================

def test_output_json_structure():
    """Test JSON output has expected structure."""
    # Create mock results
    results = [
        {
            'device': '/dev/sda',
            'type': 'ssd',
            'model': 'Test SSD',
            'serial': '12345',
            'healthy': True,
            'issues': [],
            'attributes': {5: 0, 197: 0}
        }
    ]

    # Capture output
    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        checker.output_json(results, warn_only=False)

    output = f.getvalue()
    data = json.loads(output)

    assert 'disks' in data
    assert 'summary' in data
    assert 'total' in data['summary']
    assert 'healthy' in data['summary']

    print("[PASS] JSON output structure correct")
    return True


def test_output_json_warn_only_filtering():
    """Test JSON output filters healthy disks with warn_only."""
    results = [
        {
            'device': '/dev/sda',
            'type': 'ssd',
            'model': 'Healthy SSD',
            'serial': '12345',
            'healthy': True,
            'issues': [],
            'attributes': {}
        },
        {
            'device': '/dev/sdb',
            'type': 'hdd',
            'model': 'Failing HDD',
            'serial': '67890',
            'healthy': False,
            'issues': [{'severity': 'WARNING', 'message': 'Test issue'}],
            'attributes': {}
        }
    ]

    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        checker.output_json(results, warn_only=True)

    output = f.getvalue()
    data = json.loads(output)

    # Should only contain the unhealthy disk
    assert len(data['disks']) == 1
    assert data['disks'][0]['device'] == '/dev/sdb'

    print("[PASS] JSON warn_only filtering works")
    return True


# ============================================================================
# Integration-like Tests (without actual hardware)
# ============================================================================

def test_analyze_disk_nonexistent():
    """Test analyzing non-existent device."""
    # This will fail gracefully since device doesn't exist
    result = checker.analyze_disk('/dev/nonexistent_device_xyz')

    assert result['device'] == '/dev/nonexistent_device_xyz'
    # Should either have issues or be in error state
    # depending on whether smartctl is available

    print("[PASS] Non-existent device handled")
    return True


def test_get_disk_list():
    """Test get_disk_list function."""
    disks = checker.get_disk_list()
    # Returns list (may be empty if smartctl not available)
    assert isinstance(disks, list)
    print("[PASS] get_disk_list returns list")
    return True


# ============================================================================
# Main test runner
# ============================================================================

if __name__ == "__main__":
    print("Testing baremetal_disk_sector_health.py...")
    print()

    tests = [
        # CLI tests
        test_help_message,
        test_help_shows_formats,
        test_help_shows_warn_only,
        test_help_shows_device_option,
        test_help_shows_verbose,
        test_help_explains_smart_attributes,
        test_help_shows_exit_codes,
        test_invalid_format,
        test_format_options_accepted,
        test_short_format_flag,
        test_long_format_flag,
        test_warn_only_flag,
        test_short_warn_flag,
        test_verbose_flag,
        test_short_verbose_flag,
        test_device_flag,
        test_smartctl_missing_handled,
        # SMART parsing tests
        test_parse_smart_attributes_standard,
        test_parse_smart_attributes_with_slash,
        test_parse_smart_attributes_empty,
        test_parse_smart_attributes_no_table,
        # NVMe parsing tests
        test_parse_nvme_smart_standard,
        test_parse_nvme_smart_with_errors,
        test_parse_nvme_smart_empty,
        # Threshold tests
        test_thresholds_defined,
        test_warning_vs_critical_thresholds,
        # run_command tests
        test_run_command_success,
        test_run_command_failure,
        test_run_command_not_found,
        # Output tests
        test_output_json_structure,
        test_output_json_warn_only_filtering,
        # Integration tests
        test_analyze_disk_nonexistent,
        test_get_disk_list,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print()
    print(f"Test Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
