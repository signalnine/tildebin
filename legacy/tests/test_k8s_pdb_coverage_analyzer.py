#!/usr/bin/env python3
"""
Tests for k8s_pdb_coverage_analyzer.py

Tests validate:
  - Argument parsing and help messages
  - PDB matching logic
  - Policy analysis for restrictive PDBs
  - Critical namespace detection
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

import k8s_pdb_coverage_analyzer as pdb_analyzer


def run_command(cmd_args):
    """
    Execute k8s_pdb_coverage_analyzer.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "k8s_pdb_coverage_analyzer.py"
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
    assert "pdb" in stdout.lower() or "disruption" in stdout.lower(), \
        "Help should mention PDB or disruption"


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


def test_suggest_option():
    """Validate suggest option is recognized."""
    returncode, stdout, stderr = run_command(["--suggest", "--help"])
    assert returncode == 0, "Suggest option should be valid"


def test_kind_option():
    """Validate kind filtering option is recognized."""
    for kind in ["all", "deployment", "statefulset", "replicaset"]:
        returncode, stdout, stderr = run_command(["--kind", kind, "--help"])
        assert returncode == 0, f"Kind option --kind {kind} should be valid"


def test_invalid_kind():
    """Validate invalid kind is rejected."""
    returncode, stdout, stderr = run_command(["--kind", "invalid"])
    assert returncode != 0, "Invalid kind should cause non-zero exit"


def test_combined_options():
    """Validate multiple options can be combined."""
    returncode, stdout, stderr = run_command([
        "-n", "default",
        "--format", "json",
        "--warn-only",
        "--suggest",
        "--kind", "deployment",
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


def test_plain_format_output():
    """Validate plain format output structure."""
    returncode, stdout, stderr = run_command(["--format", "plain"])

    if returncode != 2 and stdout.strip():
        lines = stdout.strip().split('\n')
        for line in lines:
            if line.strip():
                parts = line.split()
                assert len(parts) >= 4, f"Plain format should have at least 4 columns, got: {line}"


def test_table_format_output():
    """Validate table format output structure."""
    returncode, stdout, stderr = run_command(["--format", "table"])

    if returncode != 2 and stdout.strip():
        lines = stdout.strip().split('\n')
        assert len(lines) >= 2, "Table format should have header and content"
        if len(lines) > 1:
            assert '-' in lines[1], "Table should have separator line with dashes"


def test_json_format_output():
    """Validate JSON format output is valid."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        try:
            data = json.loads(stdout)
            assert isinstance(data, dict), "JSON output should be a dictionary"
            assert "summary" in data, "JSON should have 'summary' key"
            assert "workloads" in data, "JSON should have 'workloads' key"
        except json.JSONDecodeError as e:
            raise AssertionError(f"Output should be valid JSON: {e}")


def test_json_summary_structure():
    """Validate JSON summary has expected fields."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        data = json.loads(stdout)
        summary = data.get('summary', {})
        expected_fields = [
            'timestamp', 'total_workloads', 'workloads_without_pdb',
            'critical_issues', 'high_issues', 'warning_issues'
        ]
        for field in expected_fields:
            assert field in summary, f"Summary should have '{field}' field"


def test_workload_info_structure():
    """Validate workload info has required fields in JSON output."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode == 0 and stdout.strip():
        data = json.loads(stdout)
        workloads = data.get('workloads', [])

        if workloads:
            workload = workloads[0]
            required_fields = [
                'namespace', 'name', 'kind', 'replicas', 'ready_replicas',
                'has_pdb', 'pdb_names', 'issues', 'severity', 'is_critical'
            ]
            for field in required_fields:
                assert field in workload, f"Workload should have '{field}' field"


def test_severity_levels():
    """Validate severity levels are one of expected values."""
    returncode, stdout, stderr = run_command(["--format", "json"])

    if returncode != 2 and stdout.strip():
        data = json.loads(stdout)
        workloads = data.get('workloads', [])

        valid_severities = ['OK', 'LOW', 'WARNING', 'HIGH', 'CRITICAL']
        for workload in workloads:
            severity = workload.get('severity')
            assert severity in valid_severities, \
                f"Severity '{severity}' should be one of {valid_severities}"


def test_labels_match_exact():
    """Test labels_match with exact label matching."""
    selector = {'app': 'nginx', 'env': 'prod'}
    pod_labels = {'app': 'nginx', 'env': 'prod', 'version': 'v1'}

    assert pdb_analyzer.labels_match(selector, pod_labels) is True


def test_labels_match_partial():
    """Test labels_match with partial label matching."""
    selector = {'app': 'nginx'}
    pod_labels = {'app': 'nginx', 'env': 'prod'}

    assert pdb_analyzer.labels_match(selector, pod_labels) is True


def test_labels_match_mismatch():
    """Test labels_match with mismatched labels."""
    selector = {'app': 'nginx'}
    pod_labels = {'app': 'apache', 'env': 'prod'}

    assert pdb_analyzer.labels_match(selector, pod_labels) is False


def test_labels_match_empty_selector():
    """Test labels_match with empty selector."""
    selector = {}
    pod_labels = {'app': 'nginx'}

    assert pdb_analyzer.labels_match(selector, pod_labels) is False


def test_labels_match_missing_label():
    """Test labels_match when pod is missing required label."""
    selector = {'app': 'nginx', 'env': 'prod'}
    pod_labels = {'app': 'nginx'}

    assert pdb_analyzer.labels_match(selector, pod_labels) is False


def test_is_critical_namespace_true():
    """Test is_critical_namespace for known critical namespaces."""
    critical = ['kube-system', 'monitoring', 'ingress-nginx', 'cert-manager']
    for ns in critical:
        assert pdb_analyzer.is_critical_namespace(ns) is True, \
            f"{ns} should be critical"


def test_is_critical_namespace_false():
    """Test is_critical_namespace for non-critical namespaces."""
    non_critical = ['default', 'myapp', 'production', 'staging']
    for ns in non_critical:
        assert pdb_analyzer.is_critical_namespace(ns) is False, \
            f"{ns} should not be critical"


def test_analyze_pdb_policy_min_available_100_percent():
    """Test analyze_pdb_policy detects minAvailable=100%."""
    pdb = {
        'metadata': {'name': 'test-pdb'},
        'spec': {'minAvailable': '100%'}
    }
    issues = pdb_analyzer.analyze_pdb_policy(pdb, 3)

    assert any('100%' in issue and 'blocks' in issue for issue in issues), \
        "Should detect minAvailable=100% blocks evictions"


def test_analyze_pdb_policy_max_unavailable_0():
    """Test analyze_pdb_policy detects maxUnavailable=0."""
    pdb = {
        'metadata': {'name': 'test-pdb'},
        'spec': {'maxUnavailable': 0}
    }
    issues = pdb_analyzer.analyze_pdb_policy(pdb, 3)

    assert any('0' in issue and 'blocks' in issue for issue in issues), \
        "Should detect maxUnavailable=0 blocks evictions"


def test_analyze_pdb_policy_max_unavailable_0_percent():
    """Test analyze_pdb_policy detects maxUnavailable=0%."""
    pdb = {
        'metadata': {'name': 'test-pdb'},
        'spec': {'maxUnavailable': '0%'}
    }
    issues = pdb_analyzer.analyze_pdb_policy(pdb, 3)

    assert any('0%' in issue and 'blocks' in issue for issue in issues), \
        "Should detect maxUnavailable=0% blocks evictions"


def test_analyze_pdb_policy_min_equals_replicas():
    """Test analyze_pdb_policy detects minAvailable equals replicas."""
    pdb = {
        'metadata': {'name': 'test-pdb'},
        'spec': {'minAvailable': 3}
    }
    issues = pdb_analyzer.analyze_pdb_policy(pdb, 3)

    assert any('equals' in issue and 'blocks' in issue for issue in issues), \
        "Should detect minAvailable equals replicas"


def test_analyze_pdb_policy_healthy():
    """Test analyze_pdb_policy with healthy PDB configuration."""
    pdb = {
        'metadata': {'name': 'test-pdb'},
        'spec': {'maxUnavailable': 1}
    }
    issues = pdb_analyzer.analyze_pdb_policy(pdb, 3)

    assert len(issues) == 0, f"Healthy PDB should have no issues, got {issues}"


def test_suggest_pdb_single_replica():
    """Test suggest_pdb for single replica workload."""
    suggestion = pdb_analyzer.suggest_pdb('test', 1, 'Deployment')
    assert 'scaling' in suggestion.lower() or '2+' in suggestion, \
        "Should suggest scaling before PDB"


def test_suggest_pdb_two_replicas():
    """Test suggest_pdb for two replica workload."""
    suggestion = pdb_analyzer.suggest_pdb('test', 2, 'Deployment')
    assert 'maxUnavailable=1' in suggestion or 'minAvailable=1' in suggestion, \
        "Should suggest appropriate PDB for 2 replicas"


def test_suggest_pdb_many_replicas():
    """Test suggest_pdb for many replica workload."""
    suggestion = pdb_analyzer.suggest_pdb('test', 10, 'Deployment')
    assert '%' in suggestion, "Should suggest percentage-based PDB for many replicas"


def test_analyze_workload_no_pdb():
    """Test analyze_workload for workload without PDB."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'test-deploy'},
        'spec': {
            'replicas': 3,
            'selector': {'matchLabels': {'app': 'test'}}
        },
        'status': {'readyReplicas': 3}
    }
    pdbs = []

    result = pdb_analyzer.analyze_workload(workload, 'Deployment', pdbs)

    assert result['has_pdb'] is False, "Should not have PDB"
    assert result['severity'] == 'HIGH', "Multi-replica without PDB should be HIGH"
    assert any('No PDB' in issue for issue in result['issues'])


def test_analyze_workload_with_pdb():
    """Test analyze_workload for workload with matching PDB."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'test-deploy'},
        'spec': {
            'replicas': 3,
            'selector': {'matchLabels': {'app': 'test'}}
        },
        'status': {'readyReplicas': 3}
    }
    pdbs = [{
        'metadata': {'namespace': 'default', 'name': 'test-pdb'},
        'spec': {
            'selector': {'matchLabels': {'app': 'test'}},
            'maxUnavailable': 1
        }
    }]

    result = pdb_analyzer.analyze_workload(workload, 'Deployment', pdbs)

    assert result['has_pdb'] is True, "Should have PDB"
    assert 'test-pdb' in result['pdb_names']
    assert result['severity'] == 'OK', "Workload with healthy PDB should be OK"


def test_analyze_workload_critical_namespace_no_pdb():
    """Test analyze_workload for critical namespace workload without PDB."""
    workload = {
        'metadata': {'namespace': 'kube-system', 'name': 'coredns'},
        'spec': {
            'replicas': 2,
            'selector': {'matchLabels': {'app': 'coredns'}}
        },
        'status': {'readyReplicas': 2}
    }
    pdbs = []

    result = pdb_analyzer.analyze_workload(workload, 'Deployment', pdbs)

    assert result['has_pdb'] is False
    assert result['is_critical'] is True
    assert result['severity'] == 'CRITICAL', \
        "Critical namespace without PDB should be CRITICAL"


def test_analyze_workload_single_replica():
    """Test analyze_workload for single replica workload."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'test-deploy'},
        'spec': {
            'replicas': 1,
            'selector': {'matchLabels': {'app': 'test'}}
        },
        'status': {'readyReplicas': 1}
    }
    pdbs = []

    result = pdb_analyzer.analyze_workload(workload, 'Deployment', pdbs)

    assert result['severity'] == 'LOW', \
        "Single replica without PDB should be LOW (PDB wouldn't help)"


def test_analyze_workload_restrictive_pdb():
    """Test analyze_workload with overly restrictive PDB."""
    workload = {
        'metadata': {'namespace': 'default', 'name': 'test-deploy'},
        'spec': {
            'replicas': 3,
            'selector': {'matchLabels': {'app': 'test'}}
        },
        'status': {'readyReplicas': 3}
    }
    pdbs = [{
        'metadata': {'namespace': 'default', 'name': 'test-pdb'},
        'spec': {
            'selector': {'matchLabels': {'app': 'test'}},
            'minAvailable': '100%'
        }
    }]

    result = pdb_analyzer.analyze_workload(workload, 'Deployment', pdbs)

    assert result['has_pdb'] is True
    assert result['severity'] == 'WARNING', "Restrictive PDB should be WARNING"
    assert len(result['issues']) > 0, "Should have issues for restrictive PDB"


def test_find_matching_pdb_match():
    """Test find_matching_pdb finds correct PDB."""
    workload = {
        'metadata': {'namespace': 'default'},
        'spec': {'selector': {'matchLabels': {'app': 'nginx'}}}
    }
    pdbs = [
        {
            'metadata': {'namespace': 'default', 'name': 'nginx-pdb'},
            'spec': {'selector': {'matchLabels': {'app': 'nginx'}}}
        },
        {
            'metadata': {'namespace': 'default', 'name': 'other-pdb'},
            'spec': {'selector': {'matchLabels': {'app': 'other'}}}
        }
    ]

    matches = pdb_analyzer.find_matching_pdb(workload, pdbs)
    assert len(matches) == 1
    assert matches[0]['metadata']['name'] == 'nginx-pdb'


def test_find_matching_pdb_namespace_isolation():
    """Test find_matching_pdb respects namespace boundaries."""
    workload = {
        'metadata': {'namespace': 'production'},
        'spec': {'selector': {'matchLabels': {'app': 'nginx'}}}
    }
    pdbs = [{
        'metadata': {'namespace': 'staging', 'name': 'nginx-pdb'},
        'spec': {'selector': {'matchLabels': {'app': 'nginx'}}}
    }]

    matches = pdb_analyzer.find_matching_pdb(workload, pdbs)
    assert len(matches) == 0, "Should not match PDB from different namespace"


def test_find_matching_pdb_no_match():
    """Test find_matching_pdb returns empty when no match."""
    workload = {
        'metadata': {'namespace': 'default'},
        'spec': {'selector': {'matchLabels': {'app': 'nginx'}}}
    }
    pdbs = [{
        'metadata': {'namespace': 'default', 'name': 'other-pdb'},
        'spec': {'selector': {'matchLabels': {'app': 'other'}}}
    }]

    matches = pdb_analyzer.find_matching_pdb(workload, pdbs)
    assert len(matches) == 0


def test_format_plain_output_basic():
    """Test plain output formatting."""
    results = [{
        'namespace': 'default',
        'name': 'test-deploy',
        'kind': 'Deployment',
        'replicas': 3,
        'pdb_names': [],
        'severity': 'HIGH',
        'issues': ['No PDB coverage'],
        'is_critical': False
    }]

    output = pdb_analyzer.format_plain_output(results, warn_only=False)

    assert 'default' in output
    assert 'test-deploy' in output
    assert 'Deployment' in output
    assert 'HIGH' in output


def test_format_table_output_basic():
    """Test table output formatting."""
    results = [{
        'namespace': 'default',
        'name': 'test-deploy',
        'kind': 'Deployment',
        'replicas': 3,
        'pdb_names': [],
        'severity': 'HIGH',
        'issues': ['No PDB coverage'],
        'is_critical': False
    }]

    output = pdb_analyzer.format_table_output(results, warn_only=False)

    assert 'NAMESPACE' in output
    assert 'WORKLOAD' in output
    assert 'SEVERITY' in output
    assert '-' in output  # Header separator


def test_format_json_output_basic():
    """Test JSON output formatting."""
    results = [{
        'namespace': 'default',
        'name': 'test-deploy',
        'kind': 'Deployment',
        'replicas': 3,
        'ready_replicas': 3,
        'has_pdb': False,
        'pdb_names': [],
        'issues': ['No PDB coverage'],
        'severity': 'HIGH',
        'suggestion': None,
        'is_critical': False
    }]

    output = pdb_analyzer.format_json_output(results, warn_only=False)

    data = json.loads(output)
    assert 'summary' in data
    assert 'workloads' in data
    assert len(data['workloads']) == 1


def test_format_json_warn_only_filters():
    """Test JSON output with warn_only filters OK severity."""
    results = [
        {
            'namespace': 'default',
            'name': 'healthy',
            'kind': 'Deployment',
            'replicas': 3,
            'ready_replicas': 3,
            'has_pdb': True,
            'pdb_names': ['test-pdb'],
            'issues': [],
            'severity': 'OK',
            'suggestion': None,
            'is_critical': False
        },
        {
            'namespace': 'default',
            'name': 'unhealthy',
            'kind': 'Deployment',
            'replicas': 3,
            'ready_replicas': 3,
            'has_pdb': False,
            'pdb_names': [],
            'issues': ['No PDB'],
            'severity': 'HIGH',
            'suggestion': None,
            'is_critical': False
        }
    ]

    output = pdb_analyzer.format_json_output(results, warn_only=True)

    data = json.loads(output)
    assert len(data['workloads']) == 1
    assert data['workloads'][0]['name'] == 'unhealthy'


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
        test_suggest_option,
        test_kind_option,
        test_invalid_kind,
        test_combined_options,
        test_script_runs_without_kubectl,
        test_plain_format_output,
        test_table_format_output,
        test_json_format_output,
        test_json_summary_structure,
        test_workload_info_structure,
        test_severity_levels,
        test_labels_match_exact,
        test_labels_match_partial,
        test_labels_match_mismatch,
        test_labels_match_empty_selector,
        test_labels_match_missing_label,
        test_is_critical_namespace_true,
        test_is_critical_namespace_false,
        test_analyze_pdb_policy_min_available_100_percent,
        test_analyze_pdb_policy_max_unavailable_0,
        test_analyze_pdb_policy_max_unavailable_0_percent,
        test_analyze_pdb_policy_min_equals_replicas,
        test_analyze_pdb_policy_healthy,
        test_suggest_pdb_single_replica,
        test_suggest_pdb_two_replicas,
        test_suggest_pdb_many_replicas,
        test_analyze_workload_no_pdb,
        test_analyze_workload_with_pdb,
        test_analyze_workload_critical_namespace_no_pdb,
        test_analyze_workload_single_replica,
        test_analyze_workload_restrictive_pdb,
        test_find_matching_pdb_match,
        test_find_matching_pdb_namespace_isolation,
        test_find_matching_pdb_no_match,
        test_format_plain_output_basic,
        test_format_table_output_basic,
        test_format_json_output_basic,
        test_format_json_warn_only_filters,
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
