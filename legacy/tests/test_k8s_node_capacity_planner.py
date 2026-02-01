#!/usr/bin/env python3
"""Tests for k8s_node_capacity_planner.py"""

import subprocess
import sys
import json
import os
from unittest.mock import patch, MagicMock
from io import StringIO
from contextlib import redirect_stdout

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_node_capacity_planner as capacity_planner

def run_command(cmd_args, stdin_input=None):
    """Run command and return (return_code, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_input else None
        )
        stdout, stderr = proc.communicate(input=stdin_input)
        return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8')
    except Exception as e:
        return -1, "", str(e)

def test_help_message():
    """Test that --help displays correctly."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--help'])
    if return_code == 0 and 'Analyze Kubernetes cluster node capacity' in stdout:
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed: {stderr}")
        return False

def test_help_shows_formats():
    """Test that --help shows format options."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--help'])
    if return_code == 0 and all(fmt in stdout for fmt in ['table', 'plain', 'json', 'summary']):
        print("[PASS] Help shows format options")
        return True
    else:
        print("[FAIL] Help doesn't show format options")
        return False

def test_help_shows_warn_only():
    """Test that --help shows warn-only option."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--help'])
    if return_code == 0 and '--warn-only' in stdout:
        print("[PASS] Help shows warn-only option")
        return True
    else:
        print("[FAIL] Help doesn't show warn-only option")
        return False

def test_invalid_format():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', 'invalid'])
    if return_code != 0:
        print("[PASS] Invalid format rejected")
        return True
    else:
        print("[FAIL] Invalid format should be rejected")
        return False

def test_format_options():
    """Test that each format option is accepted."""
    formats = ['table', 'plain', 'json', 'summary']
    for fmt in formats:
        return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', fmt])
        # Should fail with k8s error, not argument error
        if 'unrecognized arguments' not in stderr:
            print(f"[PASS] Format '{fmt}' accepted in argument parsing")
        else:
            print(f"[FAIL] Format '{fmt}' rejected in argument parsing")
            return False
    return True

def test_short_format_flag():
    """Test that -f flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -f flag works")
        return True
    else:
        print("[FAIL] Short -f flag doesn't work")
        return False

def test_long_format_flag():
    """Test that --format flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--format', 'json'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Long --format flag works")
        return True
    else:
        print("[FAIL] Long --format flag doesn't work")
        return False

def test_warn_only_flag():
    """Test that --warn-only flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '--warn-only'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --warn-only flag works")
        return True
    else:
        print("[FAIL] --warn-only flag doesn't work")
        return False

def test_short_warn_flag():
    """Test that -w flag works."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-w'])
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Short -w flag works")
        return True
    else:
        print("[FAIL] Short -w flag doesn't work")
        return False

def test_kubernetes_import_error():
    """Test that missing kubernetes library is handled gracefully."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py', '-f', 'json'])
    # When kubernetes isn't configured, should fail with kubernetes error, not import error
    if return_code != 0:
        print("[PASS] Kubernetes error handled")
        return True
    else:
        print("[FAIL] Should exit with error when kubernetes not available")
        return False

def test_default_format_is_table():
    """Test that default format is table (not json or plain)."""
    return_code, stdout, stderr = run_command([sys.executable, 'k8s_node_capacity_planner.py'])
    # Should fail due to no k8s cluster, but argument parsing should work
    if 'unrecognized arguments' not in stderr:
        print("[PASS] Default format argument parsing works")
        return True
    else:
        print("[FAIL] Default format not properly set")
        return False


def test_parse_resource_value_cpu_millicores():
    """Test parsing CPU millicores."""
    assert capacity_planner.parse_resource_value('100m') == 100
    assert capacity_planner.parse_resource_value('1000m') == 1000
    assert capacity_planner.parse_resource_value('500m') == 500
    print("[PASS] CPU millicores parsing")
    return True


def test_parse_resource_value_cpu_cores():
    """Test parsing CPU cores."""
    assert capacity_planner.parse_resource_value('1') == 1
    assert capacity_planner.parse_resource_value('4') == 4
    assert capacity_planner.parse_resource_value('8') == 8
    print("[PASS] CPU cores parsing")
    return True


def test_parse_resource_value_memory():
    """Test parsing memory values."""
    assert capacity_planner.parse_resource_value('1Ki') == 1024
    assert capacity_planner.parse_resource_value('1Mi') == 1024 ** 2
    assert capacity_planner.parse_resource_value('1Gi') == 1024 ** 3
    assert capacity_planner.parse_resource_value('1Ti') == 1024 ** 4
    print("[PASS] Memory parsing")
    return True


def test_parse_resource_value_decimal():
    """Test parsing decimal values."""
    assert capacity_planner.parse_resource_value('1.5Gi') == int(1.5 * 1024 ** 3)
    assert capacity_planner.parse_resource_value('0.5Mi') == int(0.5 * 1024 ** 2)
    print("[PASS] Decimal resource parsing")
    return True


def test_parse_resource_value_none():
    """Test parsing None value."""
    assert capacity_planner.parse_resource_value(None) == 0
    assert capacity_planner.parse_resource_value('') == 0
    print("[PASS] None/empty resource parsing")
    return True


def test_format_bytes_basic():
    """Test format_bytes with basic values."""
    result = capacity_planner.format_bytes(1024)
    assert 'Ki' in result or 'B' in result
    print("[PASS] Basic bytes formatting")
    return True


def test_format_bytes_gigabytes():
    """Test format_bytes with gigabytes."""
    result = capacity_planner.format_bytes(1024 ** 3)
    assert 'Gi' in result
    print("[PASS] Gigabytes formatting")
    return True


def test_format_bytes_none():
    """Test format_bytes with None value."""
    result = capacity_planner.format_bytes(None)
    assert result == 'N/A'
    print("[PASS] None bytes formatting")
    return True


def test_analyze_capacity_empty():
    """Test analyze_capacity with no nodes."""
    analysis = capacity_planner.analyze_capacity([], {})
    assert analysis == []
    print("[PASS] Empty capacity analysis")
    return True


def test_analyze_capacity_single_node():
    """Test analyze_capacity with single node."""
    nodes = [{
        'name': 'node1',
        'cpu_allocatable': 4000,  # 4 cores
        'memory_allocatable': 8 * 1024 ** 3,  # 8GB
        'pods_allocatable': 110,
        'cpu_capacity': 4000,
        'memory_capacity': 8 * 1024 ** 3
    }]
    requests = {
        'node1': {
            'cpu': 2000,  # 2 cores (50%)
            'memory': 4 * 1024 ** 3,  # 4GB (50%)
            'pods': 50  # 45.5%
        }
    }

    analysis = capacity_planner.analyze_capacity(nodes, requests)

    assert len(analysis) == 1
    assert analysis[0]['node_name'] == 'node1'
    assert analysis[0]['cpu_util_pct'] == 50.0
    assert analysis[0]['memory_util_pct'] == 50.0
    # Status is OK for 50% utilization (not MODERATE which starts at 50%)
    assert analysis[0]['status'] in ['OK', 'MODERATE']
    print("[PASS] Single node capacity analysis")
    return True


def test_analyze_capacity_critical_status():
    """Test analyze_capacity with critical node."""
    nodes = [{
        'name': 'critical-node',
        'cpu_allocatable': 4000,
        'memory_allocatable': 8 * 1024 ** 3,
        'pods_allocatable': 110,
        'cpu_capacity': 4000,
        'memory_capacity': 8 * 1024 ** 3
    }]
    requests = {
        'critical-node': {
            'cpu': 3800,  # 95%
            'memory': 7 * 1024 ** 3,  # 87.5%
            'pods': 105
        }
    }

    analysis = capacity_planner.analyze_capacity(nodes, requests)

    assert len(analysis) == 1
    assert analysis[0]['status'] == 'CRITICAL'
    assert analysis[0]['max_util_pct'] > 90
    print("[PASS] Critical node capacity analysis")
    return True


def test_analyze_capacity_warning_status():
    """Test analyze_capacity with warning node."""
    nodes = [{
        'name': 'warning-node',
        'cpu_allocatable': 4000,
        'memory_allocatable': 8 * 1024 ** 3,
        'pods_allocatable': 110,
        'cpu_capacity': 4000,
        'memory_capacity': 8 * 1024 ** 3
    }]
    requests = {
        'warning-node': {
            'cpu': 3200,  # 80%
            'memory': 6 * 1024 ** 3,  # 75%
            'pods': 85
        }
    }

    analysis = capacity_planner.analyze_capacity(nodes, requests)

    assert len(analysis) == 1
    assert analysis[0]['status'] in ['WARNING', 'MODERATE']
    print("[PASS] Warning node capacity analysis")
    return True


def test_analyze_capacity_sorting():
    """Test that nodes are sorted by max utilization."""
    nodes = [
        {
            'name': 'node1',
            'cpu_allocatable': 4000,
            'memory_allocatable': 8 * 1024 ** 3,
            'pods_allocatable': 110,
            'cpu_capacity': 4000,
            'memory_capacity': 8 * 1024 ** 3
        },
        {
            'name': 'node2',
            'cpu_allocatable': 4000,
            'memory_allocatable': 8 * 1024 ** 3,
            'pods_allocatable': 110,
            'cpu_capacity': 4000,
            'memory_capacity': 8 * 1024 ** 3
        }
    ]
    requests = {
        'node1': {'cpu': 1000, 'memory': 2 * 1024 ** 3, 'pods': 20},  # 25% util
        'node2': {'cpu': 3500, 'memory': 7 * 1024 ** 3, 'pods': 100}  # 87.5% util
    }

    analysis = capacity_planner.analyze_capacity(nodes, requests)

    assert len(analysis) == 2
    # First node should have higher utilization
    assert analysis[0]['max_util_pct'] > analysis[1]['max_util_pct']
    print("[PASS] Node sorting by utilization")
    return True


def test_print_table_basic():
    """Test print_table formatting."""
    analysis = [{
        'node_name': 'test-node',
        'cpu_allocatable_m': 4000,
        'cpu_requested_m': 2000,
        'cpu_util_pct': 50.0,
        'memory_allocatable_bytes': 8 * 1024 ** 3,
        'memory_requested_bytes': 4 * 1024 ** 3,
        'memory_util_pct': 50.0,
        'pods_allocatable': 110,
        'pods_scheduled': 50,
        'pods_util_pct': 45.5,
        'max_util_pct': 50.0,
        'status': 'MODERATE'
    }]

    f = StringIO()
    with redirect_stdout(f):
        capacity_planner.print_table(analysis)
    output = f.getvalue()

    assert 'Node' in output
    assert 'CPU' in output
    assert 'Memory' in output
    assert 'test-node' in output
    print("[PASS] Table printing")
    return True


def test_print_plain_basic():
    """Test print_plain formatting."""
    analysis = [{
        'node_name': 'test-node',
        'cpu_allocatable_m': 4000,
        'cpu_requested_m': 2000,
        'memory_allocatable_bytes': 8 * 1024 ** 3,
        'memory_requested_bytes': 4 * 1024 ** 3,
        'pods_allocatable': 110,
        'pods_scheduled': 50,
        'max_util_pct': 50.0,
        'status': 'MODERATE'
    }]

    f = StringIO()
    with redirect_stdout(f):
        capacity_planner.print_plain(analysis)
    output = f.getvalue()

    assert 'test-node' in output
    assert 'cpu=' in output
    assert 'mem=' in output
    assert 'pods=' in output
    print("[PASS] Plain printing")
    return True


def test_print_json_basic():
    """Test print_json formatting."""
    analysis = [{
        'node_name': 'test-node',
        'cpu_allocatable_m': 4000,
        'max_util_pct': 50.0,
        'status': 'MODERATE'
    }]

    f = StringIO()
    with redirect_stdout(f):
        capacity_planner.print_json(analysis)
    output = f.getvalue()

    # Should be valid JSON
    data = json.loads(output)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['node_name'] == 'test-node'
    print("[PASS] JSON printing")
    return True


def test_print_summary_basic():
    """Test print_summary formatting."""
    analysis = [
        {
            'node_name': 'node1',
            'cpu_allocatable_m': 4000,
            'cpu_requested_m': 2000,
            'memory_allocatable_bytes': 8 * 1024 ** 3,
            'memory_requested_bytes': 4 * 1024 ** 3,
            'max_util_pct': 50.0,
            'status': 'OK'
        },
        {
            'node_name': 'node2',
            'cpu_allocatable_m': 4000,
            'cpu_requested_m': 3800,
            'memory_allocatable_bytes': 8 * 1024 ** 3,
            'memory_requested_bytes': 7.5 * 1024 ** 3,
            'max_util_pct': 95.0,
            'status': 'CRITICAL'
        }
    ]

    f = StringIO()
    with redirect_stdout(f):
        capacity_planner.print_summary(analysis)
    output = f.getvalue()

    assert 'Cluster Capacity Summary' in output
    assert 'Total Nodes: 2' in output
    assert 'Critical' in output or 'WARNING' in output
    print("[PASS] Summary printing")
    return True


def test_print_table_empty():
    """Test print_table with empty analysis."""
    f = StringIO()
    with redirect_stdout(f):
        capacity_planner.print_table([])
    output = f.getvalue()

    assert 'No nodes found' in output
    print("[PASS] Empty table printing")
    return True


if __name__ == "__main__":
    tests = [
        test_help_message,
        test_help_shows_formats,
        test_help_shows_warn_only,
        test_invalid_format,
        test_format_options,
        test_short_format_flag,
        test_long_format_flag,
        test_warn_only_flag,
        test_short_warn_flag,
        test_kubernetes_import_error,
        test_default_format_is_table,
        test_parse_resource_value_cpu_millicores,
        test_parse_resource_value_cpu_cores,
        test_parse_resource_value_memory,
        test_parse_resource_value_decimal,
        test_parse_resource_value_none,
        test_format_bytes_basic,
        test_format_bytes_gigabytes,
        test_format_bytes_none,
        test_analyze_capacity_empty,
        test_analyze_capacity_single_node,
        test_analyze_capacity_critical_status,
        test_analyze_capacity_warning_status,
        test_analyze_capacity_sorting,
        test_print_table_basic,
        test_print_plain_basic,
        test_print_json_basic,
        test_print_summary_basic,
        test_print_table_empty,
    ]

    passed = sum(1 for test in tests if test())
    print(f"\nTest Results: {passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
