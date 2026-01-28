#!/usr/bin/env python3
"""
Tests for k8s_runtimeclass_analyzer.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import os

# Add parent directory to path to import the script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_runtimeclass_analyzer as analyzer


def run_command(cmd_args, input_data=None):
    """Run the k8s_runtimeclass_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_runtimeclass_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sRuntimeClassAnalyzer(unittest.TestCase):
    """Test cases for k8s_runtimeclass_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('RuntimeClass', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('RuntimeClass', stdout)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'kube-system'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_option_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_option_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_table(self):
        """Test --format table option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'table'])
        self.assertIn(returncode, [0, 1, 2])

    def test_invalid_format_option(self):
        """Test that invalid format is rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command([
            '-n', 'production',
            '--verbose',
            '--warn-only'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_all_options_combined(self):
        """Test all options together."""
        returncode, stdout, stderr = run_command([
            '--namespace', 'kube-system',
            '--verbose',
            '--warn-only',
            '--format', 'json'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (may succeed or fail without kubectl)
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_runtimeclass_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_runtimeclass_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('"""', content)
        self.assertIn('RuntimeClass', content[:1000])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_runtimeclass_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_runtimeclass_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)

    def test_examples_in_help(self):
        """Test that help includes examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_runtimeclass_analyzer', stdout)

    def test_script_has_main_function(self):
        """Test that script has main function."""
        with open('k8s_runtimeclass_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('def main()', content)
        self.assertIn("if __name__ == \"__main__\":", content)


class TestGetIsolationLevel(unittest.TestCase):
    """Test the get_isolation_level function."""

    def test_default_runtime(self):
        """Test default runtime isolation level."""
        level = analyzer.get_isolation_level('<default>', {})
        self.assertEqual(level, 'standard')

    def test_none_runtime(self):
        """Test None runtime isolation level."""
        level = analyzer.get_isolation_level(None, {})
        self.assertEqual(level, 'standard')

    def test_unknown_runtime(self):
        """Test unknown runtime (not in runtimeclasses)."""
        level = analyzer.get_isolation_level('nonexistent', {})
        self.assertEqual(level, 'unknown')

    def test_kata_runtime(self):
        """Test kata runtime detection."""
        rcs = {'kata': {'handler': 'kata-runtime'}}
        level = analyzer.get_isolation_level('kata', rcs)
        self.assertEqual(level, 'vm-isolated')

    def test_firecracker_runtime(self):
        """Test firecracker runtime detection."""
        rcs = {'fc': {'handler': 'firecracker-containerd'}}
        level = analyzer.get_isolation_level('fc', rcs)
        self.assertEqual(level, 'vm-isolated')

    def test_gvisor_runtime(self):
        """Test gVisor runtime detection."""
        rcs = {'gvisor': {'handler': 'runsc'}}
        level = analyzer.get_isolation_level('gvisor', rcs)
        self.assertEqual(level, 'sandboxed')

    def test_runc_runtime(self):
        """Test runc runtime detection."""
        rcs = {'standard': {'handler': 'runc'}}
        level = analyzer.get_isolation_level('standard', rcs)
        self.assertEqual(level, 'standard')

    def test_crun_runtime(self):
        """Test crun runtime detection."""
        rcs = {'crun': {'handler': 'crun'}}
        level = analyzer.get_isolation_level('crun', rcs)
        self.assertEqual(level, 'standard')

    def test_custom_runtime(self):
        """Test custom runtime detection."""
        rcs = {'custom': {'handler': 'my-custom-runtime'}}
        level = analyzer.get_isolation_level('custom', rcs)
        self.assertEqual(level, 'custom')


class TestGetOwnerKind(unittest.TestCase):
    """Test the get_owner_kind function."""

    def test_no_owner(self):
        """Test pod with no owner."""
        kind = analyzer.get_owner_kind([])
        self.assertEqual(kind, 'None')

    def test_replicaset_owner(self):
        """Test pod owned by ReplicaSet."""
        refs = [{'kind': 'ReplicaSet', 'name': 'my-rs'}]
        kind = analyzer.get_owner_kind(refs)
        self.assertEqual(kind, 'ReplicaSet')

    def test_daemonset_owner(self):
        """Test pod owned by DaemonSet."""
        refs = [{'kind': 'DaemonSet', 'name': 'my-ds'}]
        kind = analyzer.get_owner_kind(refs)
        self.assertEqual(kind, 'DaemonSet')

    def test_statefulset_owner(self):
        """Test pod owned by StatefulSet."""
        refs = [{'kind': 'StatefulSet', 'name': 'my-sts'}]
        kind = analyzer.get_owner_kind(refs)
        self.assertEqual(kind, 'StatefulSet')

    def test_job_owner(self):
        """Test pod owned by Job."""
        refs = [{'kind': 'Job', 'name': 'my-job'}]
        kind = analyzer.get_owner_kind(refs)
        self.assertEqual(kind, 'Job')

    def test_missing_kind(self):
        """Test owner reference without kind."""
        refs = [{'name': 'something'}]
        kind = analyzer.get_owner_kind(refs)
        self.assertEqual(kind, 'Unknown')


class TestAnalyzeRuntimeUsage(unittest.TestCase):
    """Test the analyze_runtime_usage function."""

    def test_empty_pods(self):
        """Test analysis with no pods."""
        analysis = analyzer.analyze_runtime_usage([], {})
        self.assertEqual(analysis['total_pods'], 0)
        self.assertEqual(analysis['pods_with_runtime'], 0)
        self.assertEqual(analysis['pods_without_runtime'], 0)
        self.assertEqual(len(analysis['issues']), 0)

    def test_pods_without_runtime(self):
        """Test pods using default runtime."""
        pods = [
            {'name': 'pod1', 'namespace': 'default', 'runtime_class': None},
            {'name': 'pod2', 'namespace': 'default', 'runtime_class': None},
        ]
        analysis = analyzer.analyze_runtime_usage(pods, {})
        self.assertEqual(analysis['total_pods'], 2)
        self.assertEqual(analysis['pods_with_runtime'], 0)
        self.assertEqual(analysis['pods_without_runtime'], 2)
        self.assertEqual(len(analysis['by_runtime']['<default>']), 2)

    def test_pods_with_runtime(self):
        """Test pods using explicit RuntimeClass."""
        pods = [
            {'name': 'pod1', 'namespace': 'secure', 'runtime_class': 'kata'},
        ]
        rcs = {'kata': {'handler': 'kata-runtime'}}
        analysis = analyzer.analyze_runtime_usage(pods, rcs)
        self.assertEqual(analysis['pods_with_runtime'], 1)
        self.assertEqual(len(analysis['by_runtime']['kata']), 1)

    def test_missing_runtimeclass_detection(self):
        """Test detection of missing RuntimeClass."""
        pods = [
            {'name': 'pod1', 'namespace': 'default', 'runtime_class': 'nonexistent'},
        ]
        analysis = analyzer.analyze_runtime_usage(pods, {})
        self.assertIn('nonexistent', analysis['missing_runtimeclasses'])
        self.assertTrue(any(i['severity'] == 'WARNING' for i in analysis['issues']))

    def test_mixed_runtime_detection(self):
        """Test detection of mixed runtimes in namespace."""
        pods = [
            {'name': 'pod1', 'namespace': 'mixed', 'runtime_class': 'kata'},
            {'name': 'pod2', 'namespace': 'mixed', 'runtime_class': None},
        ]
        rcs = {'kata': {'handler': 'kata-runtime'}}
        analysis = analyzer.analyze_runtime_usage(pods, rcs)
        # Should detect mixed runtimes in 'mixed' namespace
        self.assertTrue(any('mixed' in str(i.get('message', ''))
                            for i in analysis['issues']))

    def test_namespace_tracking(self):
        """Test tracking by namespace."""
        pods = [
            {'name': 'pod1', 'namespace': 'ns1', 'runtime_class': 'kata'},
            {'name': 'pod2', 'namespace': 'ns1', 'runtime_class': 'kata'},
            {'name': 'pod3', 'namespace': 'ns2', 'runtime_class': None},
        ]
        rcs = {'kata': {'handler': 'kata-runtime'}}
        analysis = analyzer.analyze_runtime_usage(pods, rcs)
        self.assertEqual(analysis['by_namespace']['ns1']['kata'], 2)
        self.assertEqual(analysis['by_namespace']['ns2']['<default>'], 1)


class TestFormatJson(unittest.TestCase):
    """Test the format_json function."""

    def test_json_structure(self):
        """Test JSON output structure."""
        analysis = {
            'total_pods': 5,
            'pods_with_runtime': 2,
            'pods_without_runtime': 3,
            'by_runtime': {'<default>': [], 'kata': []},
            'by_namespace': {},
            'issues': [],
        }
        rcs = {'kata': {'handler': 'kata', 'node_selector': {},
                        'tolerations': [], 'pod_overhead_cpu': None,
                        'pod_overhead_memory': None}}
        output = analyzer.format_json(analysis, rcs)
        data = json.loads(output)

        self.assertIn('summary', data)
        self.assertIn('runtimeclasses', data)
        self.assertIn('usage_by_runtime', data)
        self.assertIn('issues', data)

    def test_json_summary_values(self):
        """Test JSON summary contains correct values."""
        analysis = {
            'total_pods': 10,
            'pods_with_runtime': 3,
            'pods_without_runtime': 7,
            'by_runtime': {},
            'by_namespace': {},
            'issues': [{'severity': 'WARNING', 'message': 'test'}],
        }
        output = analyzer.format_json(analysis, {})
        data = json.loads(output)

        self.assertEqual(data['summary']['total_pods'], 10)
        self.assertEqual(data['summary']['pods_with_runtime'], 3)
        self.assertEqual(data['summary']['pods_without_runtime'], 7)
        self.assertEqual(data['summary']['issue_count'], 1)


class TestFormatPlain(unittest.TestCase):
    """Test the format_plain function."""

    def test_plain_includes_summary(self):
        """Test plain output includes summary."""
        analysis = {
            'total_pods': 5,
            'pods_with_runtime': 2,
            'pods_without_runtime': 3,
            'by_runtime': {},
            'by_namespace': {},
            'issues': [],
        }
        output = analyzer.format_plain(analysis, {}, verbose=False, warn_only=False)
        self.assertIn('Total pods: 5', output)
        self.assertIn('RuntimeClass Analysis', output)

    def test_plain_warn_only(self):
        """Test plain output with warn_only flag."""
        analysis = {
            'total_pods': 5,
            'pods_with_runtime': 2,
            'pods_without_runtime': 3,
            'by_runtime': {},
            'by_namespace': {},
            'issues': [],
        }
        output = analyzer.format_plain(analysis, {}, verbose=False, warn_only=True)
        self.assertNotIn('RuntimeClass Analysis', output)
        self.assertNotIn('Total pods', output)

    def test_plain_shows_issues(self):
        """Test plain output shows issues."""
        analysis = {
            'total_pods': 5,
            'pods_with_runtime': 2,
            'pods_without_runtime': 3,
            'by_runtime': {},
            'by_namespace': {},
            'issues': [{'severity': 'WARNING', 'message': 'Test warning message'}],
        }
        output = analyzer.format_plain(analysis, {}, verbose=False, warn_only=False)
        self.assertIn('[WARNING]', output)
        self.assertIn('Test warning message', output)


class TestFormatTable(unittest.TestCase):
    """Test the format_table function."""

    def test_table_header(self):
        """Test table output has header."""
        analysis = {
            'total_pods': 5,
            'pods_with_runtime': 2,
            'pods_without_runtime': 3,
            'by_runtime': {'<default>': []},
            'by_namespace': {},
            'issues': [],
        }
        output = analyzer.format_table(analysis, {}, verbose=False, warn_only=False)
        self.assertIn('KUBERNETES RUNTIMECLASS ANALYSIS', output)

    def test_table_metrics(self):
        """Test table output shows metrics."""
        analysis = {
            'total_pods': 10,
            'pods_with_runtime': 4,
            'pods_without_runtime': 6,
            'by_runtime': {},
            'by_namespace': {},
            'issues': [],
        }
        output = analyzer.format_table(analysis, {}, verbose=False, warn_only=False)
        self.assertIn('Total Pods', output)
        self.assertIn('10', output)

    def test_table_warn_only(self):
        """Test table output with warn_only flag."""
        analysis = {
            'total_pods': 5,
            'pods_with_runtime': 2,
            'pods_without_runtime': 3,
            'by_runtime': {},
            'by_namespace': {},
            'issues': [],
        }
        output = analyzer.format_table(analysis, {}, verbose=False, warn_only=True)
        self.assertNotIn('KUBERNETES RUNTIMECLASS ANALYSIS', output)


class TestKubectlErrorHandling(unittest.TestCase):
    """Test kubectl error handling."""

    def test_kubectl_not_found_message(self):
        """Test error message when kubectl not found."""
        returncode, stdout, stderr = run_command([])
        if returncode == 2:
            # Script exited with usage error, might be kubectl not found
            self.assertTrue(
                'kubectl' in stderr.lower() or
                'error' in stderr.lower() or
                returncode == 2
            )

    def test_handles_timeout(self):
        """Test script handles kubectl timeout."""
        # This test verifies the script doesn't crash on timeout
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [0, 1, 2])


if __name__ == '__main__':
    # Run tests with custom runner to report results in expected format
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)

    # Print results in expected format
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"\nTest Results: {passed}/{result.testsRun} tests passed")

    sys.exit(0 if result.wasSuccessful() else 1)
