#!/usr/bin/env python3
"""
Tests for baremetal_arp_table_monitor.py

Tests validate:
  - Argument parsing and help messages
  - ARP entry parsing
  - Issue detection (duplicate MACs, incomplete entries, gateway checks)
  - Output formatting (plain, table, json)
  - Exit codes
"""

import os
import subprocess
import sys
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_command(cmd_args):
    """
    Execute baremetal_arp_table_monitor.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "baremetal_arp_table_monitor.py"
    )

    cmd = [sys.executable, script_path] + cmd_args

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr


def test_help_message():
    """Validate --help works and shows usage information."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout.lower(), "Help should contain usage information"
    assert "arp" in stdout.lower(), "Help should mention ARP"
    print("[PASS] test_help_message")
    return True


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout.lower(), "Help should contain usage information"
    print("[PASS] test_help_message_h")
    return True


def test_format_options():
    """Validate format options are recognized."""
    for fmt in ["plain", "table", "json"]:
        returncode, stdout, stderr = run_command(["--format", fmt, "--help"])
        assert returncode == 0, f"Format option --format {fmt} should be valid"
    print("[PASS] test_format_options")
    return True


def test_invalid_format():
    """Validate invalid format is rejected."""
    returncode, stdout, stderr = run_command(["--format", "invalid"])

    assert returncode != 0, "Invalid format should cause non-zero exit"
    print("[PASS] test_invalid_format")
    return True


def test_warn_only_option():
    """Validate warn-only option is recognized."""
    returncode, stdout, stderr = run_command(["--warn-only", "--help"])
    assert returncode == 0, "Warn-only option should be valid"
    print("[PASS] test_warn_only_option")
    return True


def test_verbose_option():
    """Validate verbose option is recognized."""
    returncode, stdout, stderr = run_command(["-v", "--help"])
    assert returncode == 0, "Verbose option should be valid"
    print("[PASS] test_verbose_option")
    return True


def test_combined_options():
    """Validate multiple options can be combined."""
    returncode, stdout, stderr = run_command([
        "--format", "json",
        "--warn-only",
        "-v",
        "--help"
    ])
    assert returncode == 0, "Multiple options should be valid"
    print("[PASS] test_combined_options")
    return True


def test_script_runs():
    """Validate script runs without errors."""
    returncode, stdout, stderr = run_command([])

    # Should exit with 0 (healthy), 1 (issues), or 2 (missing deps)
    assert returncode in [0, 1, 2], f"Script should exit with 0, 1, or 2, got {returncode}"
    
    # If exit code 2, should mention /proc or Linux
    if returncode == 2:
        assert "linux" in stderr.lower() or "proc" in stderr.lower(), \
            "Exit code 2 should mention Linux requirement"
    print("[PASS] test_script_runs")
    return True


def test_json_format_output():
    """Validate JSON format output is valid."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode in [0, 1] and stdout.strip():
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"
            assert "stats" in data, "JSON should have 'stats' key"
            assert "issues" in data, "JSON should have 'issues' key"
            assert "timestamp" in data, "JSON should have 'timestamp' key"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Output should be valid JSON: {e}")
    print("[PASS] test_json_format_output")
    return True


def test_table_format_output():
    """Validate table format output structure."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    if returncode in [0, 1] and stdout.strip():
        lines = stdout.strip().split('\n')
        # Should have at least header
        assert len(lines) >= 1, "Table format should have content"
        # Should have separator line with dashes
        assert any('-' in line for line in lines), "Table should have separator"
    print("[PASS] test_table_format_output")
    return True


def test_plain_format_output():
    """Validate plain format output structure."""
    returncode, stdout, stderr = run_command(["--format", "plain"])

    if returncode in [0, 1] and stdout.strip():
        assert "ARP" in stdout or "arp" in stdout.lower(), \
            "Plain output should mention ARP"
    print("[PASS] test_plain_format_output")
    return True


def test_exit_codes_documented():
    """Validate exit codes are documented in help."""
    returncode, stdout, stderr = run_command(["--help"])

    assert "Exit codes:" in stdout or "exit code" in stdout.lower(), \
        "Help should document exit codes"
    print("[PASS] test_exit_codes_documented")
    return True


def test_get_arp_entries():
    """Test ARP entry parsing function."""
    import baremetal_arp_table_monitor as monitor
    
    # This will return actual entries if on Linux, empty list otherwise
    entries = monitor.get_arp_entries()
    
    assert isinstance(entries, list), "get_arp_entries should return a list"
    
    # If entries exist, validate structure
    for entry in entries:
        assert 'ip_address' in entry, "Entry should have ip_address"
        assert 'hw_address' in entry, "Entry should have hw_address"
        assert 'device' in entry, "Entry should have device"
        assert 'state' in entry, "Entry should have state"
        assert entry['state'] in ['complete', 'incomplete'], \
            f"State should be complete or incomplete, got {entry['state']}"
    
    print("[PASS] test_get_arp_entries")
    return True


def test_get_arp_cache_limits():
    """Test ARP cache limit retrieval."""
    import baremetal_arp_table_monitor as monitor
    
    limits = monitor.get_arp_cache_limits()
    
    assert isinstance(limits, dict), "get_arp_cache_limits should return a dict"
    
    # If on Linux, should have threshold values
    if limits:
        for key in ['gc_thresh1', 'gc_thresh2', 'gc_thresh3']:
            if key in limits:
                assert isinstance(limits[key], int), f"{key} should be an integer"
    
    print("[PASS] test_get_arp_cache_limits")
    return True


def test_get_default_gateways():
    """Test default gateway detection."""
    import baremetal_arp_table_monitor as monitor
    
    gateways = monitor.get_default_gateways()
    
    assert isinstance(gateways, list), "get_default_gateways should return a list"
    
    # If gateways exist, validate structure
    for gw in gateways:
        assert 'ip' in gw, "Gateway should have ip"
        assert 'interface' in gw, "Gateway should have interface"
        # IP should look like an IP address
        parts = gw['ip'].split('.')
        assert len(parts) == 4, f"Gateway IP should have 4 octets, got {gw['ip']}"
    
    print("[PASS] test_get_default_gateways")
    return True


def test_analyze_duplicate_mac():
    """Test detection of duplicate MAC addresses."""
    import baremetal_arp_table_monitor as monitor
    
    # Create entries with duplicate MAC
    entries = [
        {'ip_address': '192.168.1.1', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': 'aa:bb:cc:dd:ee:ff', 'mask': '*', 'device': 'eth0', 'state': 'complete'},
        {'ip_address': '192.168.1.2', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': 'aa:bb:cc:dd:ee:ff', 'mask': '*', 'device': 'eth0', 'state': 'complete'},
    ]
    
    analysis = monitor.analyze_arp_table(entries, {}, [])
    
    # Should detect duplicate MAC
    dup_issues = [i for i in analysis['issues'] if i['category'] == 'duplicate_mac']
    assert len(dup_issues) == 1, "Should detect duplicate MAC"
    assert dup_issues[0]['severity'] == 'WARNING'
    
    print("[PASS] test_analyze_duplicate_mac")
    return True


def test_analyze_incomplete_entries():
    """Test detection of incomplete ARP entries."""
    import baremetal_arp_table_monitor as monitor
    
    entries = [
        {'ip_address': '192.168.1.1', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': 'aa:bb:cc:dd:ee:ff', 'mask': '*', 'device': 'eth0', 'state': 'complete'},
        {'ip_address': '192.168.1.99', 'hw_type': '0x1', 'flags': '0x0',
         'hw_address': '00:00:00:00:00:00', 'mask': '*', 'device': 'eth0', 'state': 'incomplete'},
    ]
    
    analysis = monitor.analyze_arp_table(entries, {}, [])
    
    # Should detect incomplete entry
    inc_issues = [i for i in analysis['issues'] if i['category'] == 'incomplete_entries']
    assert len(inc_issues) == 1, "Should detect incomplete entries"
    
    # Stats should be correct
    assert analysis['stats']['complete'] == 1
    assert analysis['stats']['incomplete'] == 1
    
    print("[PASS] test_analyze_incomplete_entries")
    return True


def test_analyze_gateway_unreachable():
    """Test detection of unreachable gateway."""
    import baremetal_arp_table_monitor as monitor
    
    entries = [
        {'ip_address': '192.168.1.1', 'hw_type': '0x1', 'flags': '0x0',
         'hw_address': '00:00:00:00:00:00', 'mask': '*', 'device': 'eth0', 'state': 'incomplete'},
    ]
    
    gateways = [{'ip': '192.168.1.1', 'interface': 'eth0'}]
    
    analysis = monitor.analyze_arp_table(entries, {}, gateways)
    
    # Should detect gateway unreachable
    gw_issues = [i for i in analysis['issues'] if i['category'] == 'gateway_unreachable']
    assert len(gw_issues) == 1, "Should detect unreachable gateway"
    assert gw_issues[0]['severity'] == 'CRITICAL'
    
    print("[PASS] test_analyze_gateway_unreachable")
    return True


def test_analyze_gateway_not_in_arp():
    """Test detection of gateway not in ARP table."""
    import baremetal_arp_table_monitor as monitor
    
    entries = [
        {'ip_address': '192.168.1.100', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': 'aa:bb:cc:dd:ee:ff', 'mask': '*', 'device': 'eth0', 'state': 'complete'},
    ]
    
    gateways = [{'ip': '192.168.1.1', 'interface': 'eth0'}]
    
    analysis = monitor.analyze_arp_table(entries, {}, gateways)
    
    # Should detect gateway not in ARP
    gw_issues = [i for i in analysis['issues'] if i['category'] == 'gateway_not_in_arp']
    assert len(gw_issues) == 1, "Should detect gateway not in ARP table"
    
    print("[PASS] test_analyze_gateway_not_in_arp")
    return True


def test_analyze_arp_table_full():
    """Test detection of ARP table approaching limits."""
    import baremetal_arp_table_monitor as monitor
    
    # Create many entries
    entries = [
        {'ip_address': f'192.168.1.{i}', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': f'aa:bb:cc:dd:ee:{i:02x}', 'mask': '*', 'device': 'eth0', 'state': 'complete'}
        for i in range(100)
    ]
    
    # Set low limits
    limits = {'gc_thresh1': 50, 'gc_thresh2': 80, 'gc_thresh3': 100}
    
    analysis = monitor.analyze_arp_table(entries, limits, [])
    
    # Should detect table at limit
    table_issues = [i for i in analysis['issues'] if 'arp_table' in i['category']]
    assert len(table_issues) >= 1, "Should detect ARP table limit issues"
    
    print("[PASS] test_analyze_arp_table_full")
    return True


def test_analyze_broadcast_mac():
    """Test detection of broadcast MAC in ARP entry."""
    import baremetal_arp_table_monitor as monitor
    
    entries = [
        {'ip_address': '192.168.1.100', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': 'ff:ff:ff:ff:ff:ff', 'mask': '*', 'device': 'eth0', 'state': 'complete'},
    ]
    
    analysis = monitor.analyze_arp_table(entries, {}, [])
    
    # Should detect broadcast MAC
    bc_issues = [i for i in analysis['issues'] if i['category'] == 'broadcast_mac']
    assert len(bc_issues) == 1, "Should detect broadcast MAC"
    
    print("[PASS] test_analyze_broadcast_mac")
    return True


def test_analyze_healthy_table():
    """Test analysis of healthy ARP table."""
    import baremetal_arp_table_monitor as monitor
    
    entries = [
        {'ip_address': '192.168.1.1', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': 'aa:bb:cc:dd:ee:01', 'mask': '*', 'device': 'eth0', 'state': 'complete'},
        {'ip_address': '192.168.1.2', 'hw_type': '0x1', 'flags': '0x2',
         'hw_address': 'aa:bb:cc:dd:ee:02', 'mask': '*', 'device': 'eth0', 'state': 'complete'},
    ]
    
    gateways = [{'ip': '192.168.1.1', 'interface': 'eth0'}]
    limits = {'gc_thresh1': 1024, 'gc_thresh2': 2048, 'gc_thresh3': 4096}
    
    analysis = monitor.analyze_arp_table(entries, limits, gateways)
    
    # Should have no issues
    assert len(analysis['issues']) == 0, f"Healthy table should have no issues, got {analysis['issues']}"
    assert analysis['stats']['total_entries'] == 2
    assert analysis['stats']['complete'] == 2
    assert analysis['stats']['incomplete'] == 0
    
    print("[PASS] test_analyze_healthy_table")
    return True


def test_json_output_structure():
    """Test JSON output has correct structure."""
    import baremetal_arp_table_monitor as monitor
    
    analysis = {
        'stats': {
            'total_entries': 10,
            'complete': 8,
            'incomplete': 2,
            'by_interface': {'eth0': 10}
        },
        'limits': {'gc_thresh1': 1024},
        'gateways': [{'ip': '192.168.1.1', 'interface': 'eth0'}],
        'issues': [{'severity': 'WARNING', 'category': 'test', 'message': 'Test issue'}],
        'entries': []
    }
    
    output = monitor.format_output_json(analysis)
    data = json.loads(output)
    
    assert 'timestamp' in data
    assert 'stats' in data
    assert 'issues' in data
    assert 'issue_count' in data
    assert 'has_critical' in data
    assert 'has_warnings' in data
    assert data['issue_count'] == 1
    assert data['has_warnings'] == True
    assert data['has_critical'] == False
    
    print("[PASS] test_json_output_structure")
    return True


def test_warn_only_filters_output():
    """Test that warn_only filters healthy info."""
    import baremetal_arp_table_monitor as monitor
    import io
    from contextlib import redirect_stdout
    
    analysis = {
        'stats': {
            'total_entries': 10,
            'complete': 10,
            'incomplete': 0,
            'by_interface': {'eth0': 10}
        },
        'limits': {},
        'gateways': [],
        'issues': [],
        'entries': []
    }
    
    # With warn_only=False, should have content
    output_full = monitor.format_output_plain(analysis, warn_only=False)
    assert "ARP Table Analysis" in output_full
    
    # With warn_only=True and no issues, should be minimal
    output_warn = monitor.format_output_plain(analysis, warn_only=True)
    assert "ARP Table Analysis" not in output_warn
    
    print("[PASS] test_warn_only_filters_output")
    return True


if __name__ == "__main__":
    print("Testing baremetal_arp_table_monitor.py...")
    print("=" * 60)

    tests = [
        test_help_message,
        test_help_message_h,
        test_format_options,
        test_invalid_format,
        test_warn_only_option,
        test_verbose_option,
        test_combined_options,
        test_script_runs,
        test_json_format_output,
        test_table_format_output,
        test_plain_format_output,
        test_exit_codes_documented,
        test_get_arp_entries,
        test_get_arp_cache_limits,
        test_get_default_gateways,
        test_analyze_duplicate_mac,
        test_analyze_incomplete_entries,
        test_analyze_gateway_unreachable,
        test_analyze_gateway_not_in_arp,
        test_analyze_arp_table_full,
        test_analyze_broadcast_mac,
        test_analyze_healthy_table,
        test_json_output_structure,
        test_warn_only_filters_output,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: Unexpected error: {e}")
            failed += 1

    print("=" * 60)
    print(f"Test Results: {passed}/{len(tests)} tests passed")

    sys.exit(1 if failed > 0 else 0)
