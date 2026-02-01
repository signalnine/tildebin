#!/usr/bin/env python3
"""
Tests for k8s_node_resource_fragmentation_analyzer.py

Tests argument parsing, resource parsing, fragmentation calculation logic,
and output formatting without requiring a live Kubernetes cluster.
"""

import subprocess
import sys
import json
import os
from io import StringIO
from contextlib import redirect_stdout

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_node_resource_fragmentation_analyzer as frag_analyzer


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


# === CLI Argument Tests ===

def test_help_message():
    """Test that --help displays correctly."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '--help']
    )
    if return_code == 0 and 'fragmentation' in stdout.lower():
        print("[PASS] Help message test passed")
        return True
    else:
        print(f"[FAIL] Help message test failed: rc={return_code}")
        return False


def test_help_shows_formats():
    """Test that --help shows format options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '--help']
    )
    if return_code == 0 and all(fmt in stdout for fmt in ['plain', 'table', 'json']):
        print("[PASS] Help shows format options")
        return True
    else:
        print("[FAIL] Help doesn't show all format options")
        return False


def test_help_shows_reference_pod_options():
    """Test that --help shows reference pod size options."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '--help']
    )
    if return_code == 0 and '--cpu' in stdout and '--memory' in stdout:
        print("[PASS] Help shows reference pod options")
        return True
    else:
        print("[FAIL] Help doesn't show reference pod options")
        return False


def test_invalid_format_rejected():
    """Test that invalid format is rejected."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '-f', 'invalid']
    )
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
        return_code, stdout, stderr = run_command(
            [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '-f', fmt]
        )
        # Will fail due to no kubectl, but should parse arguments OK
        if 'unrecognized arguments' in stderr:
            print(f"[FAIL] Format '{fmt}' not accepted")
            return False
    print("[PASS] All format options accepted")
    return True


def test_warn_only_flag():
    """Test that --warn-only flag is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '--warn-only']
    )
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --warn-only flag accepted")
        return True
    else:
        print("[FAIL] --warn-only flag not accepted")
        return False


def test_verbose_flag():
    """Test that --verbose flag is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '-v']
    )
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --verbose flag accepted")
        return True
    else:
        print("[FAIL] --verbose flag not accepted")
        return False


def test_namespace_flag():
    """Test that --namespace flag is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '-n', 'default']
    )
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --namespace flag accepted")
        return True
    else:
        print("[FAIL] --namespace flag not accepted")
        return False


def test_custom_cpu_reference():
    """Test that --cpu flag is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '--cpu', '1000m']
    )
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --cpu flag accepted")
        return True
    else:
        print("[FAIL] --cpu flag not accepted")
        return False


def test_custom_memory_reference():
    """Test that --memory flag is accepted."""
    return_code, stdout, stderr = run_command(
        [sys.executable, 'k8s_node_resource_fragmentation_analyzer.py', '--memory', '1Gi']
    )
    if 'unrecognized arguments' not in stderr:
        print("[PASS] --memory flag accepted")
        return True
    else:
        print("[FAIL] --memory flag not accepted")
        return False


# === Resource Parsing Tests ===

def test_parse_cpu_millicores():
    """Test parsing CPU millicores."""
    assert frag_analyzer.parse_resource_value('100m') == 100
    assert frag_analyzer.parse_resource_value('500m') == 500
    assert frag_analyzer.parse_resource_value('1000m') == 1000
    print("[PASS] CPU millicores parsing")
    return True


def test_parse_cpu_cores():
    """Test parsing CPU cores."""
    assert frag_analyzer.parse_resource_value('1') == 1000
    assert frag_analyzer.parse_resource_value('2') == 2000
    assert frag_analyzer.parse_resource_value('4') == 4000
    print("[PASS] CPU cores parsing")
    return True


def test_parse_memory_ki():
    """Test parsing memory in Ki."""
    assert frag_analyzer.parse_resource_value('1Ki') == 1024
    assert frag_analyzer.parse_resource_value('512Ki') == 512 * 1024
    print("[PASS] Memory Ki parsing")
    return True


def test_parse_memory_mi():
    """Test parsing memory in Mi."""
    assert frag_analyzer.parse_resource_value('1Mi') == 1024 ** 2
    assert frag_analyzer.parse_resource_value('512Mi') == 512 * 1024 ** 2
    print("[PASS] Memory Mi parsing")
    return True


def test_parse_memory_gi():
    """Test parsing memory in Gi."""
    assert frag_analyzer.parse_resource_value('1Gi') == 1024 ** 3
    assert frag_analyzer.parse_resource_value('8Gi') == 8 * 1024 ** 3
    print("[PASS] Memory Gi parsing")
    return True


def test_parse_empty_value():
    """Test parsing empty/None values."""
    assert frag_analyzer.parse_resource_value(None) == 0
    assert frag_analyzer.parse_resource_value('') == 0
    assert frag_analyzer.parse_resource_value('  ') == 0
    print("[PASS] Empty value parsing")
    return True


# === Formatting Tests ===

def test_format_cpu():
    """Test CPU formatting."""
    assert 'cores' in frag_analyzer.format_cpu(2000)
    assert 'm' in frag_analyzer.format_cpu(500)
    print("[PASS] CPU formatting")
    return True


def test_format_memory():
    """Test memory formatting."""
    assert 'Mi' in frag_analyzer.format_memory(1024 ** 2)
    assert 'Gi' in frag_analyzer.format_memory(1024 ** 3)
    assert frag_analyzer.format_memory(0) == '0'
    print("[PASS] Memory formatting")
    return True


# === Fragmentation Calculation Tests ===

def test_fragmentation_empty_nodes():
    """Test fragmentation calculation with no nodes."""
    results = frag_analyzer.calculate_fragmentation_metrics({}, 500, 512 * 1024 ** 2)
    assert results == []
    print("[PASS] Empty nodes fragmentation")
    return True


def test_fragmentation_single_node_ok():
    """Test fragmentation calculation for a healthy node."""
    node_info = {
        'node1': {
            'cpu_allocatable': 4000,  # 4 cores
            'memory_allocatable': 8 * 1024 ** 3,  # 8Gi
            'pods_allocatable': 110,
            'cpu_requested': 2000,  # 2 cores used
            'memory_requested': 4 * 1024 ** 3,  # 4Gi used
            'pod_count': 20,
            'pods': [],
            'is_schedulable': True,
        }
    }

    results = frag_analyzer.calculate_fragmentation_metrics(
        node_info,
        500,  # 500m reference CPU
        512 * 1024 ** 2  # 512Mi reference memory
    )

    assert len(results) == 1
    assert results[0]['node_name'] == 'node1'
    assert results[0]['cpu_free'] == 2000
    assert results[0]['memory_free'] == 4 * 1024 ** 3
    assert results[0]['schedulable_pods'] > 0
    print("[PASS] Single node OK fragmentation")
    return True


def test_fragmentation_phantom_capacity():
    """Test detection of phantom capacity (free resources but can't schedule)."""
    node_info = {
        'node1': {
            'cpu_allocatable': 4000,
            'memory_allocatable': 8 * 1024 ** 3,
            'pods_allocatable': 110,
            'cpu_requested': 3900,  # Only 100m free
            'memory_requested': 4 * 1024 ** 3,  # Plenty of memory
            'pod_count': 50,
            'pods': [],
            'is_schedulable': True,
        }
    }

    results = frag_analyzer.calculate_fragmentation_metrics(
        node_info,
        500,  # Need 500m but only 100m free
        512 * 1024 ** 2
    )

    assert len(results) == 1
    # Can't fit any reference pods because CPU is too limited
    assert results[0]['schedulable_pods'] == 0
    assert results[0]['status'] == 'PHANTOM_CAPACITY'
    print("[PASS] Phantom capacity detection")
    return True


def test_fragmentation_unschedulable_node():
    """Test that unschedulable nodes are marked correctly."""
    node_info = {
        'node1': {
            'cpu_allocatable': 4000,
            'memory_allocatable': 8 * 1024 ** 3,
            'pods_allocatable': 110,
            'cpu_requested': 1000,
            'memory_requested': 2 * 1024 ** 3,
            'pod_count': 10,
            'pods': [],
            'is_schedulable': False,  # Cordoned
        }
    }

    results = frag_analyzer.calculate_fragmentation_metrics(
        node_info,
        500,
        512 * 1024 ** 2
    )

    assert len(results) == 1
    assert results[0]['is_schedulable'] == False
    print("[PASS] Unschedulable node marking")
    return True


def test_fragmentation_limiting_factor_cpu():
    """Test that limiting factor is correctly identified as CPU."""
    node_info = {
        'node1': {
            'cpu_allocatable': 1000,  # Very limited CPU
            'memory_allocatable': 32 * 1024 ** 3,  # Lots of memory
            'pods_allocatable': 110,
            'cpu_requested': 0,
            'memory_requested': 0,
            'pod_count': 0,
            'pods': [],
            'is_schedulable': True,
        }
    }

    results = frag_analyzer.calculate_fragmentation_metrics(
        node_info,
        500,
        512 * 1024 ** 2
    )

    assert len(results) == 1
    assert results[0]['limiting_factor'] == 'cpu'
    print("[PASS] CPU limiting factor detection")
    return True


def test_fragmentation_limiting_factor_memory():
    """Test that limiting factor is correctly identified as memory."""
    node_info = {
        'node1': {
            'cpu_allocatable': 32000,  # Lots of CPU
            'memory_allocatable': 1 * 1024 ** 3,  # Very limited memory
            'pods_allocatable': 110,
            'cpu_requested': 0,
            'memory_requested': 0,
            'pod_count': 0,
            'pods': [],
            'is_schedulable': True,
        }
    }

    results = frag_analyzer.calculate_fragmentation_metrics(
        node_info,
        500,
        512 * 1024 ** 2
    )

    assert len(results) == 1
    assert results[0]['limiting_factor'] == 'memory'
    print("[PASS] Memory limiting factor detection")
    return True


def test_fragmentation_limiting_factor_pod_count():
    """Test that limiting factor is correctly identified as pod count."""
    node_info = {
        'node1': {
            'cpu_allocatable': 32000,
            'memory_allocatable': 64 * 1024 ** 3,
            'pods_allocatable': 2,  # Very limited pods
            'cpu_requested': 0,
            'memory_requested': 0,
            'pod_count': 0,
            'pods': [],
            'is_schedulable': True,
        }
    }

    results = frag_analyzer.calculate_fragmentation_metrics(
        node_info,
        500,
        512 * 1024 ** 2
    )

    assert len(results) == 1
    assert results[0]['limiting_factor'] == 'pod_count'
    assert results[0]['schedulable_pods'] == 2
    print("[PASS] Pod count limiting factor detection")
    return True


# === Cluster Summary Tests ===

def test_cluster_summary_empty():
    """Test cluster summary with no results."""
    summary = frag_analyzer.calculate_cluster_summary([], 500, 512 * 1024 ** 2)
    assert summary == {}
    print("[PASS] Empty cluster summary")
    return True


def test_cluster_summary_single_node():
    """Test cluster summary with single node."""
    results = [{
        'node_name': 'node1',
        'is_schedulable': True,
        'cpu_free': 2000,
        'memory_free': 4 * 1024 ** 3,
        'schedulable_pods': 4,
        'status': 'OK',
    }]

    summary = frag_analyzer.calculate_cluster_summary(results, 500, 512 * 1024 ** 2)

    assert summary['total_nodes'] == 1
    assert summary['schedulable_nodes'] == 1
    assert summary['total_schedulable_pods'] == 4
    print("[PASS] Single node cluster summary")
    return True


def test_cluster_summary_mixed_nodes():
    """Test cluster summary with mixed node states."""
    results = [
        {
            'node_name': 'node1',
            'is_schedulable': True,
            'cpu_free': 2000,
            'memory_free': 4 * 1024 ** 3,
            'schedulable_pods': 4,
            'status': 'OK',
        },
        {
            'node_name': 'node2',
            'is_schedulable': False,  # Cordoned
            'cpu_free': 3000,
            'memory_free': 6 * 1024 ** 3,
            'schedulable_pods': 6,
            'status': 'OK',
        },
        {
            'node_name': 'node3',
            'is_schedulable': True,
            'cpu_free': 100,
            'memory_free': 2 * 1024 ** 3,
            'schedulable_pods': 0,
            'status': 'PHANTOM_CAPACITY',
        },
    ]

    summary = frag_analyzer.calculate_cluster_summary(results, 500, 512 * 1024 ** 2)

    assert summary['total_nodes'] == 3
    assert summary['schedulable_nodes'] == 2  # node2 is not schedulable
    assert summary['phantom_capacity_nodes'] == 1
    print("[PASS] Mixed nodes cluster summary")
    return True


# === Output Format Tests ===

def test_print_plain_basic():
    """Test plain output formatting."""
    results = [{
        'node_name': 'test-node',
        'is_schedulable': True,
        'cpu_free': 2000,
        'cpu_free_pct': 50.0,
        'memory_free': 4 * 1024 ** 3,
        'memory_free_pct': 50.0,
        'schedulable_pods': 4,
        'fragmentation_score': 10.0,
        'limiting_factor': 'cpu',
        'status': 'OK',
    }]

    f = StringIO()
    with redirect_stdout(f):
        frag_analyzer.print_plain(results, {}, False)
    output = f.getvalue()

    assert 'test-node' in output
    assert 'cpu_free=' in output
    assert 'status=OK' in output
    print("[PASS] Plain output formatting")
    return True


def test_print_table_basic():
    """Test table output formatting."""
    results = [{
        'node_name': 'test-node',
        'is_schedulable': True,
        'cpu_free': 2000,
        'cpu_free_pct': 50.0,
        'memory_free': 4 * 1024 ** 3,
        'memory_free_pct': 50.0,
        'schedulable_pods': 4,
        'fragmentation_score': 10.0,
        'limiting_factor': 'cpu',
        'status': 'OK',
    }]

    f = StringIO()
    with redirect_stdout(f):
        frag_analyzer.print_table(results, {}, False)
    output = f.getvalue()

    assert 'Node' in output
    assert 'CPU Free' in output
    assert 'test-node' in output
    print("[PASS] Table output formatting")
    return True


def test_print_table_empty():
    """Test table output with no results."""
    f = StringIO()
    with redirect_stdout(f):
        frag_analyzer.print_table([], {}, False)
    output = f.getvalue()

    assert 'No nodes found' in output
    print("[PASS] Empty table output")
    return True


def test_print_json_basic():
    """Test JSON output formatting."""
    results = [{
        'node_name': 'test-node',
        'is_schedulable': True,
        'cpu_free': 2000,
        'status': 'OK',
    }]
    summary = {'total_nodes': 1}

    f = StringIO()
    with redirect_stdout(f):
        frag_analyzer.print_json(results, summary)
    output = f.getvalue()

    # Should be valid JSON
    data = json.loads(output)
    assert 'nodes' in data
    assert 'summary' in data
    assert len(data['nodes']) == 1
    assert data['nodes'][0]['node_name'] == 'test-node'
    print("[PASS] JSON output formatting")
    return True


def test_print_table_unschedulable_marker():
    """Test that unschedulable nodes are marked with asterisk."""
    results = [{
        'node_name': 'cordoned-node',
        'is_schedulable': False,
        'cpu_free': 2000,
        'cpu_free_pct': 50.0,
        'memory_free': 4 * 1024 ** 3,
        'memory_free_pct': 50.0,
        'schedulable_pods': 4,
        'fragmentation_score': 10.0,
        'limiting_factor': 'cpu',
        'status': 'OK',
    }]

    f = StringIO()
    with redirect_stdout(f):
        frag_analyzer.print_table(results, {}, True)
    output = f.getvalue()

    assert 'cordoned-node*' in output or '* = unschedulable' in output
    print("[PASS] Unschedulable node marker in table")
    return True


# === Node Allocation Tests ===

def test_calculate_node_allocations_empty():
    """Test node allocation calculation with empty data."""
    nodes_data = {'items': []}
    pods_data = {'items': []}

    result = frag_analyzer.calculate_node_allocations(nodes_data, pods_data)
    assert result == {}
    print("[PASS] Empty node allocation calculation")
    return True


def test_calculate_node_allocations_single_node():
    """Test node allocation calculation with single node."""
    nodes_data = {
        'items': [{
            'metadata': {'name': 'node1'},
            'spec': {},
            'status': {
                'allocatable': {
                    'cpu': '4',
                    'memory': '8Gi',
                    'pods': '110',
                }
            }
        }]
    }
    pods_data = {'items': []}

    result = frag_analyzer.calculate_node_allocations(nodes_data, pods_data)

    assert 'node1' in result
    assert result['node1']['cpu_allocatable'] == 4000
    assert result['node1']['memory_allocatable'] == 8 * 1024 ** 3
    assert result['node1']['is_schedulable'] == True
    print("[PASS] Single node allocation calculation")
    return True


if __name__ == "__main__":
    tests = [
        # CLI tests
        test_help_message,
        test_help_shows_formats,
        test_help_shows_reference_pod_options,
        test_invalid_format_rejected,
        test_format_options_accepted,
        test_warn_only_flag,
        test_verbose_flag,
        test_namespace_flag,
        test_custom_cpu_reference,
        test_custom_memory_reference,
        # Resource parsing tests
        test_parse_cpu_millicores,
        test_parse_cpu_cores,
        test_parse_memory_ki,
        test_parse_memory_mi,
        test_parse_memory_gi,
        test_parse_empty_value,
        # Formatting tests
        test_format_cpu,
        test_format_memory,
        # Fragmentation calculation tests
        test_fragmentation_empty_nodes,
        test_fragmentation_single_node_ok,
        test_fragmentation_phantom_capacity,
        test_fragmentation_unschedulable_node,
        test_fragmentation_limiting_factor_cpu,
        test_fragmentation_limiting_factor_memory,
        test_fragmentation_limiting_factor_pod_count,
        # Cluster summary tests
        test_cluster_summary_empty,
        test_cluster_summary_single_node,
        test_cluster_summary_mixed_nodes,
        # Output format tests
        test_print_plain_basic,
        test_print_table_basic,
        test_print_table_empty,
        test_print_json_basic,
        test_print_table_unschedulable_marker,
        # Node allocation tests
        test_calculate_node_allocations_empty,
        test_calculate_node_allocations_single_node,
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print(f"\nTest Results: {passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
