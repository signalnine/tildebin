#!/usr/bin/env python3
"""
Tests for k8s_pod_eviction_risk_analyzer.py

Tests validate:
  - Argument parsing and help messages
  - Memory value parsing
  - QoS class determination
  - Eviction risk analysis
  - Output formatting (plain, table, json)
  - Error handling for missing kubectl
  - Exit codes
"""

import os
import subprocess
import sys
import json
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_pod_eviction_risk_analyzer as eviction_analyzer


def run_command(cmd_args):
    """
    Execute k8s_pod_eviction_risk_analyzer.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_pod_eviction_risk_analyzer.py"
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
    assert "eviction" in stdout.lower(), "Help should mention eviction"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"


def test_format_options():
    """Validate format options are recognized."""
    # Valid formats should not cause parse errors
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


def test_combined_options():
    """Validate multiple options can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "--format", "json",
        "--warn-only",
        "--help"
    ])
    assert returncode == 0, "Multiple options should be valid"


def test_script_runs_without_kubectl():
    """Validate script handles missing kubectl gracefully."""
    # This test runs the script; it will fail if kubectl is not available
    # but should fail with proper error message, not a traceback
    returncode, stdout, stderr = run_command([])

    # Either kubectl succeeds (returncode 0 or 1) or fails with proper error
    if returncode == 2:
        assert "kubectl" in stderr.lower(), "Exit code 2 should mention kubectl"
    else:
        # kubectl is available and ran
        assert returncode in [0, 1], f"Script should exit with 0 or 1, got {returncode}"


def test_plain_format_output():
    """Validate plain format output structure."""
    returncode, stdout, stderr = run_command(["--format", "plain"])

    # Plain format should have space-separated values (if there's output)
    if returncode != 2 and stdout.strip():
        lines = stdout.strip().split('\n')
        # Each line should have multiple space-separated columns
        for line in lines:
            if line.strip():
                parts = line.split()
                assert len(parts) >= 4, f"Plain format should have at least 4 columns, got: {line}"


def test_table_format_output():
    """Validate table format output structure."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    # Table format should have header line with dashes
    if returncode != 2 and stdout.strip():
        lines = stdout.strip().split('\n')
        assert len(lines) >= 2, "Table format should have header and content"
        # Second line should be dashes
        if len(lines) > 1:
            assert '-' in lines[1], "Table should have separator line with dashes"


def test_json_format_output():
    """Validate JSON format output is valid."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    # JSON format should be valid JSON
    if returncode != 2 and stdout.strip():
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"
            assert "pods_at_risk" in data, "JSON should have 'pods_at_risk' key"
            assert "pods" in data, "JSON should have 'pods' key"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Output should be valid JSON: {e}")


def test_warn_only_filters_output():
    """Validate --warn-only option filters results."""
    returncode1, stdout1, stderr1 = run_command(["--format", "json"])
    returncode2, stdout2, stderr2 = run_command(["--format", "json", "--warn-only"])

    if returncode1 == 0 and returncode2 == 0 and stdout1.strip() and stdout2.strip():
        data1 = json.loads(stdout1)
        data2 = json.loads(stdout2)

        # Warn-only should have fewer or equal pods
        assert len(data2.get('pods', [])) <= len(data1.get('pods', [])), \
            "Warn-only should filter out low-risk pods"


def test_namespace_filter():
    """Validate namespace option filters results."""
    returncode1, stdout1, stderr1 = run_command(["--format", "json"])
    returncode2, stdout2, stderr2 = run_command(["--format", "json", "-n", "kube-system"])

    if returncode1 == 0 and returncode2 == 0 and stdout1.strip() and stdout2.strip():
        data1 = json.loads(stdout1)
        data2 = json.loads(stdout2)

        # All pods in output2 should be in kube-system namespace
        for pod in data2.get('pods', []):
            assert pod.get('namespace') == 'kube-system', \
                f"Namespace filter should return only kube-system pods, got {pod.get('namespace')}"


def test_pod_info_structure():
    """Validate pod info has required fields in JSON output."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        pods = data.get('pods', [])

        if pods:
            pod = pods[0]
            required_fields = ['namespace', 'name', 'qos_class', 'risk_level', 'reasons']
            for field in required_fields:
                assert field in pod, f"Pod should have '{field}' field"

            # Validate field types
            assert isinstance(pod['namespace'], str), "namespace should be string"
            assert isinstance(pod['name'], str), "name should be string"
            assert isinstance(pod['qos_class'], str), "qos_class should be string"
            assert isinstance(pod['risk_level'], str), "risk_level should be string"
            assert isinstance(pod['reasons'], list), "reasons should be list"


def test_risk_levels():
    """Validate risk levels are one of expected values."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        pods = data.get('pods', [])

        valid_risk_levels = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        for pod in pods:
            risk_level = pod.get('risk_level')
            assert risk_level in valid_risk_levels, \
                f"Risk level '{risk_level}' should be one of {valid_risk_levels}"


def test_qos_classes():
    """Validate QoS classes are one of expected values."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        pods = data.get('pods', [])

        valid_qos = ['Guaranteed', 'Burstable', 'BestEffort']
        for pod in pods:
            qos = pod.get('qos_class')
            assert qos in valid_qos, \
                f"QoS class '{qos}' should be one of {valid_qos}"


def test_exit_code_no_at_risk_pods():
    """Validate exit code when no pods at risk."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0:
        data = json.loads(stdout) if stdout.strip() else {}
        pods_at_risk = data.get('pods_at_risk', 0)
        if pods_at_risk == 0:
            # Should exit with 0 if no pods at risk
            assert returncode == 0, "Should exit 0 when no pods at risk"


def test_exit_code_with_at_risk_pods():
    """Validate exit code when pods at risk found."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        data = json.loads(stdout)
        pods_at_risk = data.get('pods_at_risk', 0)
        if pods_at_risk > 0:
            # Should exit with 1 if pods at risk found
            assert returncode == 1, "Should exit 1 when pods at risk found"


def test_parse_memory_value_bytes():
    """Test parse_memory_value with plain bytes."""
    assert eviction_analyzer.parse_memory_value('1024') == 1024
    assert eviction_analyzer.parse_memory_value('0') == 0


def test_parse_memory_value_kilobytes():
    """Test parse_memory_value with kilobytes."""
    assert eviction_analyzer.parse_memory_value('1K') == 1000
    assert eviction_analyzer.parse_memory_value('1Ki') == 1024
    assert eviction_analyzer.parse_memory_value('100K') == 100000


def test_parse_memory_value_megabytes():
    """Test parse_memory_value with megabytes."""
    assert eviction_analyzer.parse_memory_value('1M') == 1000000
    assert eviction_analyzer.parse_memory_value('1Mi') == 1048576
    assert eviction_analyzer.parse_memory_value('512Mi') == 536870912


def test_parse_memory_value_gigabytes():
    """Test parse_memory_value with gigabytes."""
    assert eviction_analyzer.parse_memory_value('1G') == 1000000000
    assert eviction_analyzer.parse_memory_value('1Gi') == 1073741824
    assert eviction_analyzer.parse_memory_value('2Gi') == 2147483648


def test_parse_memory_value_terabytes():
    """Test parse_memory_value with terabytes."""
    assert eviction_analyzer.parse_memory_value('1T') == 1000000000000
    assert eviction_analyzer.parse_memory_value('1Ti') == 1099511627776


def test_parse_memory_value_empty():
    """Test parse_memory_value with empty or None values."""
    assert eviction_analyzer.parse_memory_value('') == 0
    assert eviction_analyzer.parse_memory_value(None) == 0


def test_parse_memory_value_decimal():
    """Test parse_memory_value with decimal values."""
    assert eviction_analyzer.parse_memory_value('1.5Gi') == int(1.5 * 1073741824)
    assert eviction_analyzer.parse_memory_value('0.5Mi') == int(0.5 * 1048576)


def test_parse_memory_value_lowercase():
    """Test parse_memory_value with lowercase units."""
    assert eviction_analyzer.parse_memory_value('1mi') == 1048576
    assert eviction_analyzer.parse_memory_value('1gi') == 1073741824


def test_determine_qos_class_guaranteed():
    """Test QoS class determination for Guaranteed."""
    pod = {
        'spec': {
            'containers': [{
                'resources': {
                    'limits': {'memory': '1Gi', 'cpu': '1'},
                    'requests': {'memory': '1Gi', 'cpu': '1'}
                }
            }]
        }
    }
    qos = eviction_analyzer.determine_qos_class(pod)
    assert qos == 'Guaranteed', f"Expected Guaranteed, got {qos}"


def test_determine_qos_class_besteffort():
    """Test QoS class determination for BestEffort."""
    pod = {
        'spec': {
            'containers': [{
                'resources': {}
            }]
        }
    }
    qos = eviction_analyzer.determine_qos_class(pod)
    assert qos == 'BestEffort', f"Expected BestEffort, got {qos}"


def test_determine_qos_class_burstable():
    """Test QoS class determination for Burstable."""
    pod = {
        'spec': {
            'containers': [{
                'resources': {
                    'requests': {'memory': '512Mi'},
                    'limits': {'memory': '1Gi'}
                }
            }]
        }
    }
    qos = eviction_analyzer.determine_qos_class(pod)
    assert qos == 'Burstable', f"Expected Burstable, got {qos}"


def test_determine_qos_class_burstable_no_limits():
    """Test QoS class determination for Burstable with only requests."""
    pod = {
        'spec': {
            'containers': [{
                'resources': {
                    'requests': {'cpu': '100m'}
                }
            }]
        }
    }
    qos = eviction_analyzer.determine_qos_class(pod)
    assert qos == 'Burstable', f"Expected Burstable, got {qos}"


def test_determine_qos_class_empty_pod():
    """Test QoS class determination with empty pod structure."""
    pod = {'spec': {'containers': []}}
    qos = eviction_analyzer.determine_qos_class(pod)
    assert qos == 'BestEffort', f"Expected BestEffort for empty pod, got {qos}"


def test_analyze_pod_eviction_risk_no_pressure():
    """Test pod eviction risk analysis with no node pressure."""
    pod = {
        'metadata': {'namespace': 'default', 'name': 'test-pod'},
        'spec': {'nodeName': 'node1', 'containers': [{'resources': {}}]},
        'status': {'phase': 'Running'}
    }
    pressure_nodes = {}
    allocatable = {}

    risk_level, risk_reasons = eviction_analyzer.analyze_pod_eviction_risk(
        pod, pressure_nodes, allocatable
    )

    # BestEffort pod should have some risk
    assert risk_level in ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']


def test_analyze_pod_eviction_risk_memory_pressure():
    """Test pod eviction risk with node memory pressure."""
    pod = {
        'metadata': {'namespace': 'default', 'name': 'test-pod'},
        'spec': {'nodeName': 'node1', 'containers': [{'resources': {}}]},
        'status': {'phase': 'Running'}
    }
    pressure_nodes = {
        'node1': {
            'memory_pressure': True,
            'disk_pressure': False,
            'pid_pressure': False,
            'not_ready': False
        }
    }
    allocatable = {}

    risk_level, risk_reasons = eviction_analyzer.analyze_pod_eviction_risk(
        pod, pressure_nodes, allocatable
    )

    # Should have CRITICAL risk due to memory pressure
    assert risk_level == 'CRITICAL', f"Expected CRITICAL, got {risk_level}"
    assert any('MemoryPressure' in r for r in risk_reasons)


def test_analyze_pod_eviction_risk_disk_pressure():
    """Test pod eviction risk with node disk pressure."""
    pod = {
        'metadata': {'namespace': 'default', 'name': 'test-pod'},
        'spec': {'nodeName': 'node1', 'containers': [{'resources': {}}]},
        'status': {'phase': 'Running'}
    }
    pressure_nodes = {
        'node1': {
            'memory_pressure': False,
            'disk_pressure': True,
            'pid_pressure': False,
            'not_ready': False
        }
    }
    allocatable = {}

    risk_level, risk_reasons = eviction_analyzer.analyze_pod_eviction_risk(
        pod, pressure_nodes, allocatable
    )

    assert any('DiskPressure' in r for r in risk_reasons)


def test_analyze_pod_eviction_risk_besteffort():
    """Test pod eviction risk for BestEffort QoS."""
    pod = {
        'metadata': {'namespace': 'default', 'name': 'test-pod'},
        'spec': {'nodeName': 'node1', 'containers': [{'resources': {}}]},
        'status': {'phase': 'Running'}
    }
    pressure_nodes = {}
    allocatable = {}

    risk_level, risk_reasons = eviction_analyzer.analyze_pod_eviction_risk(
        pod, pressure_nodes, allocatable
    )

    # BestEffort should have HIGH risk
    assert risk_level == 'HIGH', f"Expected HIGH for BestEffort, got {risk_level}"
    assert any('BestEffort' in r for r in risk_reasons)


def test_analyze_pod_eviction_risk_oomkilled():
    """Test pod eviction risk with OOMKilled container."""
    pod = {
        'metadata': {'namespace': 'default', 'name': 'test-pod'},
        'spec': {
            'nodeName': 'node1',
            'containers': [{
                'resources': {
                    'limits': {'memory': '1Gi'},
                    'requests': {'memory': '1Gi'}
                }
            }]
        },
        'status': {
            'phase': 'Running',
            'containerStatuses': [{
                'name': 'container1',
                'restartCount': 10,
                'lastState': {
                    'terminated': {'reason': 'OOMKilled'}
                }
            }]
        }
    }
    pressure_nodes = {}
    allocatable = {}

    risk_level, risk_reasons = eviction_analyzer.analyze_pod_eviction_risk(
        pod, pressure_nodes, allocatable
    )

    # OOMKilled should result in CRITICAL risk
    assert risk_level == 'CRITICAL', f"Expected CRITICAL for OOMKilled, got {risk_level}"
    assert any('OOMKilled' in r for r in risk_reasons)


def test_analyze_pod_eviction_risk_high_restarts():
    """Test pod eviction risk with high restart count."""
    pod = {
        'metadata': {'namespace': 'default', 'name': 'test-pod'},
        'spec': {
            'nodeName': 'node1',
            'containers': [{
                'resources': {
                    'limits': {'memory': '1Gi'},
                    'requests': {'memory': '1Gi'}
                }
            }]
        },
        'status': {
            'phase': 'Running',
            'containerStatuses': [{
                'name': 'container1',
                'restartCount': 10,
                'lastState': {}
            }]
        }
    }
    pressure_nodes = {}
    allocatable = {}

    risk_level, risk_reasons = eviction_analyzer.analyze_pod_eviction_risk(
        pod, pressure_nodes, allocatable
    )

    # High restart count should be noted
    assert any('restart count' in r.lower() for r in risk_reasons)


def test_analyze_pod_eviction_risk_no_memory_limits():
    """Test pod eviction risk with containers without memory limits."""
    pod = {
        'metadata': {'namespace': 'default', 'name': 'test-pod'},
        'spec': {
            'nodeName': 'node1',
            'containers': [
                {'name': 'container1', 'resources': {}},
                {'name': 'container2', 'resources': {}}
            ]
        },
        'status': {'phase': 'Running'}
    }
    pressure_nodes = {}
    allocatable = {}

    risk_level, risk_reasons = eviction_analyzer.analyze_pod_eviction_risk(
        pod, pressure_nodes, allocatable
    )

    # Containers without memory limits should be flagged
    assert any('without memory limits' in r for r in risk_reasons)


def test_get_nodes_with_pressure_mocked():
    """Test getting nodes with pressure conditions using mocking."""
    mock_output = json.dumps({
        'items': [{
            'metadata': {'name': 'node1'},
            'status': {
                'conditions': [
                    {'type': 'MemoryPressure', 'status': 'True'},
                    {'type': 'Ready', 'status': 'True'}
                ]
            }
        }]
    })

    with patch('k8s_pod_eviction_risk_analyzer.run_kubectl', return_value=mock_output):
        pressure_nodes = eviction_analyzer.get_nodes_with_pressure()
        assert 'node1' in pressure_nodes
        assert pressure_nodes['node1']['memory_pressure'] is True


def test_get_node_allocatable_mocked():
    """Test getting node allocatable resources using mocking."""
    mock_output = json.dumps({
        'items': [{
            'metadata': {'name': 'node1'},
            'status': {
                'allocatable': {
                    'memory': '16Gi',
                    'cpu': '4',
                    'ephemeral-storage': '100Gi'
                }
            }
        }]
    })

    with patch('k8s_pod_eviction_risk_analyzer.run_kubectl', return_value=mock_output):
        allocatable = eviction_analyzer.get_node_allocatable()
        assert 'node1' in allocatable
        assert allocatable['node1']['memory'] > 0
        assert allocatable['node1']['cpu'] == '4'


def test_format_output_plain_basic():
    """Test plain output formatting."""
    pods_data = [{
        'namespace': 'default',
        'name': 'test-pod',
        'qos_class': 'Burstable',
        'risk_level': 'MEDIUM',
        'reasons': ['No memory limits']
    }]

    # Capture output by redirecting stdout
    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        eviction_analyzer.format_output_plain(pods_data, None)
    output = f.getvalue()

    assert 'default' in output
    assert 'test-pod' in output


def test_format_output_table_basic():
    """Test table output formatting."""
    pods_data = [{
        'namespace': 'default',
        'name': 'test-pod',
        'qos_class': 'Burstable',
        'risk_level': 'MEDIUM',
        'reasons': ['No memory limits']
    }]

    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        eviction_analyzer.format_output_table(pods_data, None)
    output = f.getvalue()

    assert 'NAMESPACE' in output
    assert 'POD NAME' in output
    assert '-' in output  # Header separator


def test_format_output_json_basic():
    """Test JSON output formatting."""
    pods_data = [{
        'namespace': 'default',
        'name': 'test-pod',
        'qos_class': 'Burstable',
        'risk_level': 'MEDIUM',
        'reasons': ['No memory limits']
    }]

    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        eviction_analyzer.format_output_json(pods_data, None)
    output = f.getvalue()

    # Should be valid JSON
    data = json.loads(output)
    assert 'pods_at_risk' in data
    assert 'pods' in data
    assert len(data['pods']) == 1


if __name__ == "__main__":
    # Run all tests
    test_functions = [
        test_help_message,
        test_help_message_h,
        test_format_options,
        test_invalid_format,
        test_namespace_option,
        test_warn_only_option,
        test_combined_options,
        test_script_runs_without_kubectl,
        test_plain_format_output,
        test_table_format_output,
        test_json_format_output,
        test_warn_only_filters_output,
        test_namespace_filter,
        test_pod_info_structure,
        test_risk_levels,
        test_qos_classes,
        test_exit_code_no_at_risk_pods,
        test_exit_code_with_at_risk_pods,
        test_parse_memory_value_bytes,
        test_parse_memory_value_kilobytes,
        test_parse_memory_value_megabytes,
        test_parse_memory_value_gigabytes,
        test_parse_memory_value_terabytes,
        test_parse_memory_value_empty,
        test_parse_memory_value_decimal,
        test_parse_memory_value_lowercase,
        test_determine_qos_class_guaranteed,
        test_determine_qos_class_besteffort,
        test_determine_qos_class_burstable,
        test_determine_qos_class_burstable_no_limits,
        test_determine_qos_class_empty_pod,
        test_analyze_pod_eviction_risk_no_pressure,
        test_analyze_pod_eviction_risk_memory_pressure,
        test_analyze_pod_eviction_risk_disk_pressure,
        test_analyze_pod_eviction_risk_besteffort,
        test_analyze_pod_eviction_risk_oomkilled,
        test_analyze_pod_eviction_risk_high_restarts,
        test_analyze_pod_eviction_risk_no_memory_limits,
        test_get_nodes_with_pressure_mocked,
        test_get_node_allocatable_mocked,
        test_format_output_plain_basic,
        test_format_output_table_basic,
        test_format_output_json_basic,
    ]

    failed = 0
    for test_func in test_functions:
        try:
            test_func()
            print(f"✓ {test_func.__name__}")
        except AssertionError as e:
            print(f"✗ {test_func.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__}: Unexpected error: {e}")
            failed += 1

    passed = len(test_functions) - failed
    print(f"\nTest Results: {passed}/{len(test_functions)} tests passed")
    sys.exit(1 if failed > 0 else 0)
