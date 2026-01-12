#!/usr/bin/env python3
"""
Tests for k8s_pod_topology_analyzer.py

Tests validate:
  - Argument parsing and help messages
  - Topology spread constraint analysis
  - Pod affinity/anti-affinity analysis
  - Pod distribution analysis
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

import k8s_pod_topology_analyzer as topology_analyzer


def run_command(cmd_args):
    """
    Execute k8s_pod_topology_analyzer.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_pod_topology_analyzer.py"
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
    assert "usage:" in stdout, "Help should contain usage information"
    assert "topology" in stdout.lower(), "Help should mention topology"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"


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


def test_verbose_option():
    """Validate verbose option is recognized."""
    returncode, stdout, stderr = run_command(["-v", "--help"])
    assert returncode == 0, "Verbose option should be valid"


def test_combined_options():
    """Validate multiple options can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "--format", "json",
        "--warn-only",
        "-v",
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
            assert "summary" in data, "JSON should have 'summary' key"
            assert "workloads" in data, "JSON should have 'workloads' key"
            assert "distribution_issues" in data, "JSON should have 'distribution_issues' key"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Output should be valid JSON: {e}")


def test_table_format_output():
    """Validate table format output structure."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    if returncode != 2 and stdout.strip():
        # Table format should have header and separator
        assert '-' in stdout or 'WORKLOAD' in stdout or 'No' in stdout, \
            "Table should have recognizable structure"


def test_analyze_topology_spread_constraints_empty():
    """Test topology constraint analysis with empty spec."""
    pod_spec = {}
    result = topology_analyzer.analyze_topology_spread_constraints(pod_spec)

    assert result['has_constraints'] is False
    assert result['constraints'] == []
    assert result['topology_keys'] == []


def test_analyze_topology_spread_constraints_with_zone():
    """Test topology constraint analysis with zone spread."""
    pod_spec = {
        'topologySpreadConstraints': [{
            'topologyKey': 'topology.kubernetes.io/zone',
            'maxSkew': 1,
            'whenUnsatisfiable': 'DoNotSchedule',
            'labelSelector': {'matchLabels': {'app': 'test'}}
        }]
    }
    result = topology_analyzer.analyze_topology_spread_constraints(pod_spec)

    assert result['has_constraints'] is True
    assert len(result['constraints']) == 1
    assert 'topology.kubernetes.io/zone' in result['topology_keys']
    assert result['constraints'][0]['max_skew'] == 1
    assert result['constraints'][0]['when_unsatisfiable'] == 'DoNotSchedule'


def test_analyze_topology_spread_constraints_multiple():
    """Test topology constraint analysis with multiple constraints."""
    pod_spec = {
        'topologySpreadConstraints': [
            {
                'topologyKey': 'topology.kubernetes.io/zone',
                'maxSkew': 1,
                'whenUnsatisfiable': 'DoNotSchedule'
            },
            {
                'topologyKey': 'kubernetes.io/hostname',
                'maxSkew': 1,
                'whenUnsatisfiable': 'ScheduleAnyway'
            }
        ]
    }
    result = topology_analyzer.analyze_topology_spread_constraints(pod_spec)

    assert result['has_constraints'] is True
    assert len(result['constraints']) == 2
    assert len(result['topology_keys']) == 2


def test_analyze_affinity_empty():
    """Test affinity analysis with empty spec."""
    pod_spec = {}
    result = topology_analyzer.analyze_affinity(pod_spec)

    assert result['has_pod_affinity'] is False
    assert result['has_pod_anti_affinity'] is False
    assert result['has_node_affinity'] is False


def test_analyze_affinity_pod_anti_affinity_required():
    """Test affinity analysis with required pod anti-affinity."""
    pod_spec = {
        'affinity': {
            'podAntiAffinity': {
                'requiredDuringSchedulingIgnoredDuringExecution': [{
                    'topologyKey': 'kubernetes.io/hostname',
                    'labelSelector': {'matchLabels': {'app': 'test'}}
                }]
            }
        }
    }
    result = topology_analyzer.analyze_affinity(pod_spec)

    assert result['has_pod_anti_affinity'] is True
    assert len(result['pod_anti_affinity_rules']) == 1
    assert result['pod_anti_affinity_rules'][0]['type'] == 'required'


def test_analyze_affinity_pod_anti_affinity_preferred():
    """Test affinity analysis with preferred pod anti-affinity."""
    pod_spec = {
        'affinity': {
            'podAntiAffinity': {
                'preferredDuringSchedulingIgnoredDuringExecution': [{
                    'weight': 100,
                    'podAffinityTerm': {
                        'topologyKey': 'topology.kubernetes.io/zone',
                        'labelSelector': {'matchLabels': {'app': 'test'}}
                    }
                }]
            }
        }
    }
    result = topology_analyzer.analyze_affinity(pod_spec)

    assert result['has_pod_anti_affinity'] is True
    assert len(result['pod_anti_affinity_rules']) == 1
    assert result['pod_anti_affinity_rules'][0]['type'] == 'preferred'
    assert result['pod_anti_affinity_rules'][0]['weight'] == 100


def test_analyze_affinity_pod_affinity():
    """Test affinity analysis with pod affinity."""
    pod_spec = {
        'affinity': {
            'podAffinity': {
                'requiredDuringSchedulingIgnoredDuringExecution': [{
                    'topologyKey': 'kubernetes.io/hostname',
                    'labelSelector': {'matchLabels': {'app': 'cache'}}
                }]
            }
        }
    }
    result = topology_analyzer.analyze_affinity(pod_spec)

    assert result['has_pod_affinity'] is True
    assert len(result['pod_affinity_rules']) == 1


def test_analyze_affinity_node_affinity():
    """Test affinity analysis with node affinity."""
    pod_spec = {
        'affinity': {
            'nodeAffinity': {
                'requiredDuringSchedulingIgnoredDuringExecution': {
                    'nodeSelectorTerms': [{
                        'matchExpressions': [{
                            'key': 'node-type',
                            'operator': 'In',
                            'values': ['compute']
                        }]
                    }]
                }
            }
        }
    }
    result = topology_analyzer.analyze_affinity(pod_spec)

    assert result['has_node_affinity'] is True


def test_analyze_workload_no_constraints():
    """Test workload analysis without topology constraints."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'test-deploy'},
        'spec': {
            'replicas': 3,
            'template': {
                'spec': {
                    'containers': [{'name': 'app', 'image': 'nginx'}]
                }
            }
        }
    }
    result = topology_analyzer.analyze_workload(workload, 'Deployment')

    assert result['namespace'] == 'default'
    assert result['name'] == 'test-deploy'
    assert result['kind'] == 'Deployment'
    assert result['replicas'] == 3
    assert result['has_topology_constraints'] is False
    assert len(result['issues']) > 0  # Should flag missing constraints


def test_analyze_workload_with_topology_constraints():
    """Test workload analysis with topology constraints."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'test-deploy'},
        'spec': {
            'replicas': 3,
            'template': {
                'spec': {
                    'topologySpreadConstraints': [{
                        'topologyKey': 'topology.kubernetes.io/zone',
                        'maxSkew': 1,
                        'whenUnsatisfiable': 'DoNotSchedule'
                    }],
                    'containers': [{'name': 'app', 'image': 'nginx'}]
                }
            }
        }
    }
    result = topology_analyzer.analyze_workload(workload, 'Deployment')

    assert result['has_topology_constraints'] is True
    assert 'topology.kubernetes.io/zone' in result['topology_keys']


def test_analyze_workload_single_replica():
    """Test workload analysis with single replica - should not flag issues."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'singleton'},
        'spec': {
            'replicas': 1,
            'template': {
                'spec': {
                    'containers': [{'name': 'app', 'image': 'nginx'}]
                }
            }
        }
    }
    result = topology_analyzer.analyze_workload(workload, 'Deployment')

    assert result['replicas'] == 1
    # Single replica shouldn't flag topology issues
    assert len([i for i in result['issues'] if 'topology' in i.lower()]) == 0


def test_analyze_workload_with_anti_affinity():
    """Test workload analysis with pod anti-affinity instead of topology spread."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'test-deploy'},
        'spec': {
            'replicas': 3,
            'template': {
                'spec': {
                    'affinity': {
                        'podAntiAffinity': {
                            'requiredDuringSchedulingIgnoredDuringExecution': [{
                                'topologyKey': 'kubernetes.io/hostname',
                                'labelSelector': {'matchLabels': {'app': 'test'}}
                            }]
                        }
                    },
                    'containers': [{'name': 'app', 'image': 'nginx'}]
                }
            }
        }
    }
    result = topology_analyzer.analyze_workload(workload, 'Deployment')

    assert result['has_pod_anti_affinity'] is True
    # Should not flag missing topology constraints if anti-affinity is present


def test_analyze_pod_distribution_single_node():
    """Test pod distribution analysis when all pods on single node."""
    pods = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'test-pod-1',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'test-rs'}]
                },
                'spec': {'nodeName': 'node1'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'test-pod-2',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'test-rs'}]
                },
                'spec': {'nodeName': 'node1'}
            }
        ]
    }
    nodes = {
        'node1': {'zone': 'zone-a', 'region': 'region-1', 'hostname': 'node1', 'labels': {}},
        'node2': {'zone': 'zone-b', 'region': 'region-1', 'hostname': 'node2', 'labels': {}}
    }

    issues = topology_analyzer.analyze_pod_distribution(pods, nodes)

    assert len(issues) > 0
    assert any('single node' in i['issues'][0].lower() for i in issues)


def test_analyze_pod_distribution_balanced():
    """Test pod distribution analysis when pods are balanced."""
    pods = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'test-pod-1',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'test-rs'}]
                },
                'spec': {'nodeName': 'node1'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'test-pod-2',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'test-rs'}]
                },
                'spec': {'nodeName': 'node2'}
            }
        ]
    }
    nodes = {
        'node1': {'zone': 'zone-a', 'region': 'region-1', 'hostname': 'node1', 'labels': {}},
        'node2': {'zone': 'zone-b', 'region': 'region-1', 'hostname': 'node2', 'labels': {}}
    }

    issues = topology_analyzer.analyze_pod_distribution(pods, nodes)

    # No issues when balanced
    assert len(issues) == 0


def test_analyze_pod_distribution_single_zone():
    """Test pod distribution analysis when all pods in single zone."""
    pods = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'test-pod-1',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'test-rs'}]
                },
                'spec': {'nodeName': 'node1'}
            },
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'test-pod-2',
                    'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'test-rs'}]
                },
                'spec': {'nodeName': 'node2'}
            }
        ]
    }
    nodes = {
        'node1': {'zone': 'zone-a', 'region': 'region-1', 'hostname': 'node1', 'labels': {}},
        'node2': {'zone': 'zone-a', 'region': 'region-1', 'hostname': 'node2', 'labels': {}}
    }

    issues = topology_analyzer.analyze_pod_distribution(pods, nodes)

    # Should flag single zone
    assert len(issues) > 0
    assert any('single zone' in ' '.join(i['issues']).lower() for i in issues)


def test_analyze_pod_distribution_standalone_pod():
    """Test pod distribution analysis ignores standalone pods."""
    pods = {
        'items': [
            {
                'metadata': {
                    'namespace': 'default',
                    'name': 'standalone-pod',
                    'ownerReferences': []
                },
                'spec': {'nodeName': 'node1'}
            }
        ]
    }
    nodes = {
        'node1': {'zone': 'zone-a', 'region': 'region-1', 'hostname': 'node1', 'labels': {}}
    }

    issues = topology_analyzer.analyze_pod_distribution(pods, nodes)

    # Single pod shouldn't generate issues
    assert len(issues) == 0


def test_format_output_plain():
    """Test plain output formatting."""
    results = {
        'workloads': [{
            'namespace': 'default',
            'name': 'test',
            'kind': 'Deployment',
            'replicas': 3,
            'severity': 'WARNING',
            'issues': ['No topology constraints']
        }],
        'distribution_issues': []
    }

    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        topology_analyzer.format_output_plain(results)
    output = f.getvalue()

    assert 'default' in output
    assert 'Deployment' in output


def test_format_output_table():
    """Test table output formatting."""
    results = {
        'workloads': [{
            'namespace': 'default',
            'name': 'test',
            'kind': 'Deployment',
            'replicas': 3,
            'has_topology_constraints': False,
            'severity': 'WARNING',
            'issues': ['No topology constraints']
        }],
        'distribution_issues': []
    }

    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        topology_analyzer.format_output_table(results)
    output = f.getvalue()

    assert 'WORKLOAD' in output
    assert 'NAMESPACE' in output
    assert '-' in output


def test_format_output_json():
    """Test JSON output formatting."""
    results = {
        'summary': {'total_workloads': 1},
        'workloads': [{
            'namespace': 'default',
            'name': 'test',
            'kind': 'Deployment',
            'replicas': 3,
            'severity': 'WARNING',
            'issues': []
        }],
        'distribution_issues': []
    }

    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        topology_analyzer.format_output_json(results)
    output = f.getvalue()

    data = json.loads(output)
    assert 'summary' in data
    assert 'workloads' in data


def test_get_nodes_mocked():
    """Test getting nodes with mocking."""
    mock_output = json.dumps({
        'items': [{
            'metadata': {
                'name': 'node1',
                'labels': {
                    'topology.kubernetes.io/zone': 'zone-a',
                    'topology.kubernetes.io/region': 'region-1',
                    'kubernetes.io/hostname': 'node1'
                }
            }
        }]
    })

    with patch('k8s_pod_topology_analyzer.run_kubectl', return_value=mock_output):
        nodes = topology_analyzer.get_nodes()
        assert 'node1' in nodes
        assert nodes['node1']['zone'] == 'zone-a'


def test_summary_structure():
    """Test JSON output summary structure."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        data = json.loads(stdout)
        summary = data.get('summary', {})

        assert 'total_workloads' in summary
        assert 'workloads_with_issues' in summary
        assert 'distribution_issues' in summary
        assert 'total_nodes' in summary


if __name__ == "__main__":
    # Run all tests
    test_functions = [
        test_help_message,
        test_help_message_h,
        test_format_options,
        test_invalid_format,
        test_namespace_option,
        test_warn_only_option,
        test_verbose_option,
        test_combined_options,
        test_script_runs_without_kubectl,
        test_json_format_output,
        test_table_format_output,
        test_analyze_topology_spread_constraints_empty,
        test_analyze_topology_spread_constraints_with_zone,
        test_analyze_topology_spread_constraints_multiple,
        test_analyze_affinity_empty,
        test_analyze_affinity_pod_anti_affinity_required,
        test_analyze_affinity_pod_anti_affinity_preferred,
        test_analyze_affinity_pod_affinity,
        test_analyze_affinity_node_affinity,
        test_analyze_workload_no_constraints,
        test_analyze_workload_with_topology_constraints,
        test_analyze_workload_single_replica,
        test_analyze_workload_with_anti_affinity,
        test_analyze_pod_distribution_single_node,
        test_analyze_pod_distribution_balanced,
        test_analyze_pod_distribution_single_zone,
        test_analyze_pod_distribution_standalone_pod,
        test_format_output_plain,
        test_format_output_table,
        test_format_output_json,
        test_get_nodes_mocked,
        test_summary_structure,
    ]

    failed = 0
    for test_func in test_functions:
        try:
            test_func()
            print(f"PASS {test_func.__name__}")
        except AssertionError as e:
            print(f"FAIL {test_func.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"FAIL {test_func.__name__}: Unexpected error: {e}")
            failed += 1

    passed = len(test_functions) - failed
    print(f"\nTest Results: {passed}/{len(test_functions)} tests passed")
    sys.exit(1 if failed > 0 else 0)
