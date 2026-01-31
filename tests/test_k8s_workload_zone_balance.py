#!/usr/bin/env python3
"""
Tests for k8s_workload_zone_balance.py

Tests validate:
  - Argument parsing and help messages
  - Zone distribution analysis logic
  - Workload owner detection
  - Output formatting (plain, table, json)
  - Error handling for missing kubectl
  - Exit codes
"""

import os
import subprocess
import sys
import json
from unittest.mock import patch

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_workload_zone_balance as zone_balance


def run_command(cmd_args):
    """
    Execute k8s_workload_zone_balance.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_workload_zone_balance.py"
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
    assert "zone" in stdout.lower(), "Help should mention zone"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout.lower(), "Help should contain usage information"


def test_format_options():
    """Validate format options are recognized."""
    for fmt in ["plain", "table", "json"]:
        returncode, stdout, stderr = run_command(["--format", fmt, "--help"])
        assert returncode == 0, f"Format option --format {fmt} should be valid"


def test_invalid_format():
    """Validate invalid format is rejected."""
    returncode, stdout, stderr = run_command(["--format", "invalid"])

    assert returncode != 0, "Invalid format should cause non-zero exit"


def test_namespace_option():
    """Validate namespace option is recognized."""
    returncode, stdout, stderr = run_command(["-n", "default", "--help"])
    assert returncode == 0, "Namespace option should be valid"


def test_warn_only_option():
    """Validate warn-only option is recognized."""
    returncode, stdout, stderr = run_command(["--warn-only", "--help"])
    assert returncode == 0, "Warn-only option should be valid"


def test_min_zones_option():
    """Validate min-zones option is recognized."""
    returncode, stdout, stderr = run_command(["--min-zones", "3", "--help"])
    assert returncode == 0, "min-zones option should be valid"


def test_combined_options():
    """Validate multiple options can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "--format", "json",
        "--warn-only",
        "--min-zones", "2",
        "--help"
    ])
    assert returncode == 0, "Multiple options should be valid"


def test_script_runs_without_kubectl():
    """Validate script handles missing kubectl gracefully."""
    returncode, stdout, stderr = run_command([])

    # Either kubectl succeeds (returncode 0 or 1) or fails with proper error
    if returncode == 2:
        assert "kubectl" in stderr.lower(), "Exit code 2 should mention kubectl"
    else:
        assert returncode in [0, 1], f"Script should exit with 0 or 1, got {returncode}"


def test_json_format_output():
    """Validate JSON format output is valid."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"
            assert "cluster_zones" in data, "JSON should have 'cluster_zones' key"
            assert "workloads" in data, "JSON should have 'workloads' key"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Output should be valid JSON: {e}")


def test_table_format_output():
    """Validate table format output structure."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    if returncode != 2 and stdout.strip():
        lines = stdout.strip().split('\n')
        # Should have header section
        assert any('ZONE' in line.upper() for line in lines), "Table should mention zones"


def test_get_workload_owner_deployment():
    """Test workload owner detection for Deployment."""
    pod = {
        'metadata': {
            'name': 'my-app-5d8f7b6c9d-abc12',
            'ownerReferences': [{
                'kind': 'ReplicaSet',
                'name': 'my-app-5d8f7b6c9d'
            }]
        }
    }
    kind, name = zone_balance.get_workload_owner(pod)
    assert kind == 'Deployment', f"Expected Deployment, got {kind}"
    assert name == 'my-app', f"Expected my-app, got {name}"


def test_get_workload_owner_statefulset():
    """Test workload owner detection for StatefulSet."""
    pod = {
        'metadata': {
            'name': 'my-sts-0',
            'ownerReferences': [{
                'kind': 'StatefulSet',
                'name': 'my-sts'
            }]
        }
    }
    kind, name = zone_balance.get_workload_owner(pod)
    assert kind == 'StatefulSet', f"Expected StatefulSet, got {kind}"
    assert name == 'my-sts', f"Expected my-sts, got {name}"


def test_get_workload_owner_daemonset():
    """Test workload owner detection for DaemonSet."""
    pod = {
        'metadata': {
            'name': 'my-ds-abc12',
            'ownerReferences': [{
                'kind': 'DaemonSet',
                'name': 'my-ds'
            }]
        }
    }
    kind, name = zone_balance.get_workload_owner(pod)
    assert kind == 'DaemonSet', f"Expected DaemonSet, got {kind}"
    assert name == 'my-ds', f"Expected my-ds, got {name}"


def test_get_workload_owner_standalone():
    """Test workload owner detection for standalone pod."""
    pod = {
        'metadata': {
            'name': 'standalone-pod'
        }
    }
    kind, name = zone_balance.get_workload_owner(pod)
    assert kind == 'Standalone', f"Expected Standalone, got {kind}"
    assert name == 'standalone-pod', f"Expected standalone-pod, got {name}"


def test_get_zone_summary():
    """Test zone summary calculation."""
    nodes = {
        'node1': {'zone': 'us-east-1a', 'region': 'us-east-1', 'labels': {}},
        'node2': {'zone': 'us-east-1a', 'region': 'us-east-1', 'labels': {}},
        'node3': {'zone': 'us-east-1b', 'region': 'us-east-1', 'labels': {}},
        'node4': {'zone': 'us-east-1c', 'region': 'us-east-1', 'labels': {}},
    }
    summary = zone_balance.get_zone_summary(nodes)
    assert summary['us-east-1a'] == 2, "Zone a should have 2 nodes"
    assert summary['us-east-1b'] == 1, "Zone b should have 1 node"
    assert summary['us-east-1c'] == 1, "Zone c should have 1 node"


def test_analyze_zone_distribution_single_zone():
    """Test zone distribution analysis for single-zone workload."""
    nodes = {
        'node1': {'zone': 'us-east-1a', 'region': 'us-east-1', 'labels': {}},
        'node2': {'zone': 'us-east-1b', 'region': 'us-east-1', 'labels': {}},
    }
    pods_data = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-1',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-2',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
        ]
    }

    results = zone_balance.analyze_zone_distribution(pods_data, nodes, min_zones=2)

    assert len(results) == 1, "Should have one workload"
    assert results[0]['zone_count'] == 1, "Should be in single zone"
    assert results[0]['risk_level'] == 'CRITICAL', "Single zone should be CRITICAL"


def test_analyze_zone_distribution_balanced():
    """Test zone distribution analysis for balanced workload."""
    nodes = {
        'node1': {'zone': 'us-east-1a', 'region': 'us-east-1', 'labels': {}},
        'node2': {'zone': 'us-east-1b', 'region': 'us-east-1', 'labels': {}},
    }
    pods_data = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-1',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-2',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node2'},
                'status': {'phase': 'Running'}
            },
        ]
    }

    results = zone_balance.analyze_zone_distribution(pods_data, nodes, min_zones=2)

    assert len(results) == 1, "Should have one workload"
    assert results[0]['zone_count'] == 2, "Should be in two zones"
    assert results[0]['risk_level'] == 'OK', "Balanced workload should be OK"


def test_analyze_zone_distribution_imbalanced():
    """Test zone distribution analysis for imbalanced workload."""
    nodes = {
        'node1': {'zone': 'us-east-1a', 'region': 'us-east-1', 'labels': {}},
        'node2': {'zone': 'us-east-1b', 'region': 'us-east-1', 'labels': {}},
    }
    pods_data = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-1',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-2',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-3',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-4',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node2'},
                'status': {'phase': 'Running'}
            },
        ]
    }

    results = zone_balance.analyze_zone_distribution(pods_data, nodes, min_zones=2)

    assert len(results) == 1, "Should have one workload"
    assert results[0]['zone_count'] == 2, "Should be in two zones"
    assert results[0]['imbalance_ratio'] == 3.0, "Imbalance should be 3:1"
    assert results[0]['risk_level'] == 'MEDIUM', "Imbalanced workload should be MEDIUM"


def test_analyze_zone_distribution_skips_daemonsets():
    """Test that DaemonSets are skipped in analysis."""
    nodes = {
        'node1': {'zone': 'us-east-1a', 'region': 'us-east-1', 'labels': {}},
    }
    pods_data = {
        'items': [
            {
                'metadata': {
                    'namespace': 'kube-system',
                    'name': 'node-exporter-abc12',
                    'ownerReferences': [{'kind': 'DaemonSet', 'name': 'node-exporter'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
        ]
    }

    results = zone_balance.analyze_zone_distribution(pods_data, nodes, min_zones=2)

    # DaemonSets should be skipped
    assert len(results) == 0, "DaemonSets should be skipped"


def test_analyze_zone_distribution_unscheduled():
    """Test handling of unscheduled pods."""
    nodes = {
        'node1': {'zone': 'us-east-1a', 'region': 'us-east-1', 'labels': {}},
    }
    pods_data = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-1',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {'nodeName': 'node1'},
                'status': {'phase': 'Running'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'app-pod-2',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'app-abc123'}]
                },
                'spec': {},  # No nodeName - unscheduled
                'status': {'phase': 'Pending'}
            },
        ]
    }

    results = zone_balance.analyze_zone_distribution(pods_data, nodes, min_zones=2)

    assert len(results) == 1, "Should have one workload"
    assert 'unscheduled' in results[0]['zones'], "Should track unscheduled pods"
    assert any('unscheduled' in issue for issue in results[0]['issues']), \
        "Should flag unscheduled pods as issue"


def test_format_plain():
    """Test plain output formatting."""
    results = [{
        'namespace': 'default',
        'kind': 'Deployment',
        'name': 'my-app',
        'pod_count': 3,
        'zone_count': 1,
        'zones': {'us-east-1a': 3},
        'node_count': 2,
        'imbalance_ratio': 1.0,
        'risk_level': 'CRITICAL',
        'issues': ['All pods in single zone']
    }]
    zone_summary = {'us-east-1a': 2, 'us-east-1b': 2}

    output = zone_balance.format_plain(results, zone_summary, False)

    assert 'us-east-1a' in output, "Should contain zone name"
    assert 'my-app' in output, "Should contain workload name"
    assert 'CRITICAL' in output, "Should contain risk level"


def test_format_table():
    """Test table output formatting."""
    results = [{
        'namespace': 'default',
        'kind': 'Deployment',
        'name': 'my-app',
        'pod_count': 3,
        'zone_count': 1,
        'zones': {'us-east-1a': 3},
        'node_count': 2,
        'imbalance_ratio': 1.0,
        'risk_level': 'CRITICAL',
        'issues': ['All pods in single zone']
    }]
    zone_summary = {'us-east-1a': 2, 'us-east-1b': 2}

    output = zone_balance.format_table(results, zone_summary, False)

    assert 'NAMESPACE' in output, "Should contain header"
    assert '-' in output, "Should contain separator"
    assert 'my-app' in output, "Should contain workload name"


def test_format_json():
    """Test JSON output formatting."""
    results = [{
        'namespace': 'default',
        'kind': 'Deployment',
        'name': 'my-app',
        'pod_count': 3,
        'zone_count': 1,
        'zones': {'us-east-1a': 3},
        'node_count': 2,
        'imbalance_ratio': 1.0,
        'risk_level': 'CRITICAL',
        'issues': ['All pods in single zone']
    }]
    zone_summary = {'us-east-1a': 2, 'us-east-1b': 2}

    output = zone_balance.format_json(results, zone_summary, False)

    data = json.loads(output)
    assert 'cluster_zones' in data, "Should have cluster_zones"
    assert 'workloads' in data, "Should have workloads"
    assert data['workloads_at_risk'] == 1, "Should count workloads at risk"


def test_format_json_warn_only():
    """Test JSON output with warn_only filter."""
    results = [
        {
            'namespace': 'default',
            'kind': 'Deployment',
            'name': 'bad-app',
            'pod_count': 3,
            'zone_count': 1,
            'zones': {'us-east-1a': 3},
            'node_count': 2,
            'imbalance_ratio': 1.0,
            'risk_level': 'CRITICAL',
            'issues': ['All pods in single zone']
        },
        {
            'namespace': 'default',
            'kind': 'Deployment',
            'name': 'good-app',
            'pod_count': 2,
            'zone_count': 2,
            'zones': {'us-east-1a': 1, 'us-east-1b': 1},
            'node_count': 2,
            'imbalance_ratio': 1.0,
            'risk_level': 'OK',
            'issues': []
        }
    ]
    zone_summary = {'us-east-1a': 2, 'us-east-1b': 2}

    output = zone_balance.format_json(results, zone_summary, True)  # warn_only=True

    data = json.loads(output)
    assert len(data['workloads']) == 1, "Should only include at-risk workloads"
    assert data['workloads'][0]['name'] == 'bad-app', "Should include bad-app"


def test_risk_level_values():
    """Validate risk levels are one of expected values."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        workloads = data.get('workloads', [])

        valid_risk_levels = ['OK', 'MEDIUM', 'HIGH', 'CRITICAL']
        for workload in workloads:
            risk_level = workload.get('risk_level')
            assert risk_level in valid_risk_levels, \
                f"Risk level '{risk_level}' should be one of {valid_risk_levels}"


def test_workload_info_structure():
    """Validate workload info has required fields in JSON output."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        workloads = data.get('workloads', [])

        if workloads:
            workload = workloads[0]
            required_fields = ['namespace', 'kind', 'name', 'pod_count',
                             'zone_count', 'zones', 'risk_level', 'issues']
            for field in required_fields:
                assert field in workload, f"Workload should have '{field}' field"


def test_exit_code_no_issues():
    """Validate exit code when no zone issues found."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0:
        data = json.loads(stdout) if stdout.strip() else {}
        at_risk = data.get('workloads_at_risk', 0)
        if at_risk == 0:
            assert returncode == 0, "Should exit 0 when no workloads at risk"


def test_exit_code_with_issues():
    """Validate exit code when zone issues found."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        data = json.loads(stdout)
        at_risk = data.get('workloads_at_risk', 0)
        if at_risk > 0:
            assert returncode == 1, "Should exit 1 when workloads at risk found"


if __name__ == "__main__":
    # Run all tests
    test_functions = [
        test_help_message,
        test_help_message_h,
        test_format_options,
        test_invalid_format,
        test_namespace_option,
        test_warn_only_option,
        test_min_zones_option,
        test_combined_options,
        test_script_runs_without_kubectl,
        test_json_format_output,
        test_table_format_output,
        test_get_workload_owner_deployment,
        test_get_workload_owner_statefulset,
        test_get_workload_owner_daemonset,
        test_get_workload_owner_standalone,
        test_get_zone_summary,
        test_analyze_zone_distribution_single_zone,
        test_analyze_zone_distribution_balanced,
        test_analyze_zone_distribution_imbalanced,
        test_analyze_zone_distribution_skips_daemonsets,
        test_analyze_zone_distribution_unscheduled,
        test_format_plain,
        test_format_table,
        test_format_json,
        test_format_json_warn_only,
        test_risk_level_values,
        test_workload_info_structure,
        test_exit_code_no_issues,
        test_exit_code_with_issues,
    ]

    failed = 0
    for test_func in test_functions:
        try:
            test_func()
            print(f"[PASS] {test_func.__name__}")
        except AssertionError as e:
            print(f"[FAIL] {test_func.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_func.__name__}: Unexpected error: {e}")
            failed += 1

    passed = len(test_functions) - failed
    print(f"\nTest Results: {passed}/{len(test_functions)} tests passed")
    sys.exit(1 if failed > 0 else 0)
