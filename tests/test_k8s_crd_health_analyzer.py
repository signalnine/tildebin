#!/usr/bin/env python3
"""
Tests for k8s_crd_health_analyzer.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_crd_health_analyzer as crd_analyzer


def run_command(cmd_args, input_data=None):
    """Run the k8s_crd_health_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_crd_health_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sCrdHealthAnalyzer(unittest.TestCase):
    """Test cases for k8s_crd_health_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('CRD', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--check-resources', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('CRD', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl) or 1 (kubectl error)
        self.assertIn(returncode, [1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_format_option_short(self):
        """Test -f short option works."""
        returncode, stdout, stderr = run_command(['-f', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_invalid_format(self):
        """Test that invalid format values are rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [1, 2])

    def test_check_resources_option(self):
        """Test --check-resources option is accepted."""
        returncode, stdout, stderr = run_command(['--check-resources'])
        self.assertIn(returncode, [1, 2])

    def test_check_resources_short(self):
        """Test -c short option works."""
        returncode, stdout, stderr = run_command(['-c'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [1, 2])

    def test_group_filter_option(self):
        """Test --group option is accepted."""
        returncode, stdout, stderr = run_command(['--group', 'cert-manager.io'])
        self.assertIn(returncode, [1, 2])

    def test_group_filter_short(self):
        """Test -g short option works."""
        returncode, stdout, stderr = run_command(['-g', 'monitoring.coreos.com'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-v'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command([
            '--format', 'plain',
            '--warn-only',
            '--verbose',
            '--group', 'test.example.com'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        self.assertNotEqual(returncode, 0)
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_crd_health_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_crd_health_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('"""', content)
        self.assertIn('CRD', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_crd_health_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestAnalyzeCrd(unittest.TestCase):
    """Test analyze_crd function."""

    def test_healthy_crd(self):
        """Test analysis of healthy CRD."""
        crd = {
            'metadata': {'name': 'certificates.cert-manager.io'},
            'spec': {
                'group': 'cert-manager.io',
                'scope': 'Namespaced',
                'names': {
                    'plural': 'certificates',
                    'kind': 'Certificate'
                },
                'versions': [
                    {'name': 'v1', 'served': True, 'storage': True}
                ],
                'conversion': {'strategy': 'None'}
            },
            'status': {
                'conditions': [
                    {'type': 'Established', 'status': 'True'},
                    {'type': 'NamesAccepted', 'status': 'True'}
                ]
            }
        }

        result = crd_analyzer.analyze_crd(crd, check_resources=False)

        self.assertTrue(result['healthy'])
        self.assertEqual(len(result['issues']), 0)
        self.assertEqual(result['name'], 'certificates.cert-manager.io')
        self.assertEqual(result['group'], 'cert-manager.io')
        self.assertEqual(result['kind'], 'Certificate')
        self.assertEqual(result['storage_version'], 'v1')

    def test_crd_not_established(self):
        """Test CRD that is not established."""
        crd = {
            'metadata': {'name': 'broken.example.com'},
            'spec': {
                'group': 'example.com',
                'scope': 'Namespaced',
                'names': {'plural': 'brokens', 'kind': 'Broken'},
                'versions': [{'name': 'v1', 'served': True, 'storage': True}],
                'conversion': {'strategy': 'None'}
            },
            'status': {
                'conditions': [
                    {'type': 'Established', 'status': 'False'},
                    {'type': 'NamesAccepted', 'status': 'True'}
                ]
            }
        }

        result = crd_analyzer.analyze_crd(crd, check_resources=False)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('not established' in issue for issue in result['issues']))

    def test_crd_names_not_accepted(self):
        """Test CRD with name conflict."""
        crd = {
            'metadata': {'name': 'conflicting.example.com'},
            'spec': {
                'group': 'example.com',
                'scope': 'Namespaced',
                'names': {'plural': 'conflictings', 'kind': 'Conflicting'},
                'versions': [{'name': 'v1', 'served': True, 'storage': True}],
                'conversion': {'strategy': 'None'}
            },
            'status': {
                'conditions': [
                    {'type': 'Established', 'status': 'True'},
                    {'type': 'NamesAccepted', 'status': 'False'}
                ]
            }
        }

        result = crd_analyzer.analyze_crd(crd, check_resources=False)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('not accepted' in issue for issue in result['issues']))

    def test_crd_multiple_versions_no_webhook(self):
        """Test CRD with multiple versions but no conversion webhook."""
        crd = {
            'metadata': {'name': 'multiversion.example.com'},
            'spec': {
                'group': 'example.com',
                'scope': 'Namespaced',
                'names': {'plural': 'multiversions', 'kind': 'MultiVersion'},
                'versions': [
                    {'name': 'v1', 'served': True, 'storage': True},
                    {'name': 'v1beta1', 'served': True, 'storage': False}
                ],
                'conversion': {'strategy': 'None'}
            },
            'status': {
                'conditions': [
                    {'type': 'Established', 'status': 'True'},
                    {'type': 'NamesAccepted', 'status': 'True'}
                ]
            }
        }

        result = crd_analyzer.analyze_crd(crd, check_resources=False)

        self.assertTrue(any('Multiple served versions' in issue for issue in result['issues']))
        self.assertTrue(any('without conversion webhook' in issue for issue in result['issues']))

    def test_crd_deprecated_v1beta1(self):
        """Test CRD with deprecated v1beta1 version."""
        crd = {
            'metadata': {'name': 'legacy.example.com'},
            'spec': {
                'group': 'example.com',
                'scope': 'Namespaced',
                'names': {'plural': 'legacies', 'kind': 'Legacy'},
                'versions': [
                    {'name': 'v1beta1', 'served': True, 'storage': True}
                ],
                'conversion': {'strategy': 'None'}
            },
            'status': {
                'conditions': [
                    {'type': 'Established', 'status': 'True'},
                    {'type': 'NamesAccepted', 'status': 'True'}
                ]
            }
        }

        result = crd_analyzer.analyze_crd(crd, check_resources=False)

        self.assertTrue(any('deprecated v1beta1' in issue for issue in result['issues']))

    def test_crd_with_conversion_webhook(self):
        """Test CRD with proper conversion webhook."""
        crd = {
            'metadata': {'name': 'converted.example.com'},
            'spec': {
                'group': 'example.com',
                'scope': 'Namespaced',
                'names': {'plural': 'converteds', 'kind': 'Converted'},
                'versions': [
                    {'name': 'v1', 'served': True, 'storage': True},
                    {'name': 'v1beta1', 'served': True, 'storage': False}
                ],
                'conversion': {
                    'strategy': 'Webhook',
                    'webhook': {
                        'conversionReviewVersions': ['v1', 'v1beta1']
                    }
                }
            },
            'status': {
                'conditions': [
                    {'type': 'Established', 'status': 'True'},
                    {'type': 'NamesAccepted', 'status': 'True'}
                ]
            }
        }

        result = crd_analyzer.analyze_crd(crd, check_resources=False)

        # Should not have the "without conversion webhook" warning
        self.assertFalse(any('without conversion webhook' in issue for issue in result['issues']))
        self.assertEqual(result['conversion_strategy'], 'Webhook')

    def test_crd_cluster_scoped(self):
        """Test cluster-scoped CRD."""
        crd = {
            'metadata': {'name': 'clusterwide.example.com'},
            'spec': {
                'group': 'example.com',
                'scope': 'Cluster',
                'names': {'plural': 'clusterwides', 'kind': 'ClusterWide'},
                'versions': [{'name': 'v1', 'served': True, 'storage': True}],
                'conversion': {'strategy': 'None'}
            },
            'status': {
                'conditions': [
                    {'type': 'Established', 'status': 'True'},
                    {'type': 'NamesAccepted', 'status': 'True'}
                ]
            }
        }

        result = crd_analyzer.analyze_crd(crd, check_resources=False)

        self.assertEqual(result['scope'], 'Cluster')
        self.assertTrue(result['healthy'])


class TestPrintResults(unittest.TestCase):
    """Test print_results function."""

    def test_print_results_json_format(self):
        """Test print_results with JSON format."""
        results = [{
            'name': 'test.example.com',
            'group': 'example.com',
            'kind': 'Test',
            'scope': 'Namespaced',
            'versions': ['v1'],
            'served_versions': ['v1'],
            'storage_version': 'v1',
            'conversion_strategy': 'None',
            'established': True,
            'names_accepted': True,
            'resource_count': 5,
            'issues': [],
            'healthy': True
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = crd_analyzer.print_results(results, 'json', False, False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'test.example.com')

    def test_print_results_plain_format(self):
        """Test print_results with plain format."""
        results = [{
            'name': 'test.example.com',
            'group': 'example.com',
            'kind': 'Test',
            'scope': 'Namespaced',
            'versions': ['v1'],
            'served_versions': ['v1'],
            'storage_version': 'v1',
            'conversion_strategy': 'None',
            'established': True,
            'names_accepted': True,
            'resource_count': 0,
            'issues': [],
            'healthy': True
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = crd_analyzer.print_results(results, 'plain', False, False)

        output = f.getvalue()
        self.assertIn('test.example.com', output)
        self.assertIn('Summary:', output)

    def test_print_results_warn_only(self):
        """Test print_results with warn_only flag."""
        results = [
            {
                'name': 'healthy.example.com',
                'group': 'example.com',
                'kind': 'Healthy',
                'scope': 'Namespaced',
                'versions': ['v1'],
                'served_versions': ['v1'],
                'storage_version': 'v1',
                'conversion_strategy': 'None',
                'established': True,
                'names_accepted': True,
                'resource_count': 5,
                'issues': [],
                'healthy': True
            },
            {
                'name': 'unhealthy.example.com',
                'group': 'example.com',
                'kind': 'Unhealthy',
                'scope': 'Namespaced',
                'versions': ['v1'],
                'served_versions': ['v1'],
                'storage_version': 'v1',
                'conversion_strategy': 'None',
                'established': False,
                'names_accepted': True,
                'resource_count': 0,
                'issues': ['CRD not established'],
                'healthy': False
            }
        ]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = crd_analyzer.print_results(results, 'json', True, False)

        output = f.getvalue()
        data = json.loads(output)

        # Only unhealthy CRD should be in output
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'unhealthy.example.com')
        self.assertTrue(has_issues)

    def test_print_results_verbose(self):
        """Test print_results with verbose flag."""
        results = [{
            'name': 'test.example.com',
            'group': 'example.com',
            'kind': 'Test',
            'scope': 'Namespaced',
            'versions': ['v1'],
            'served_versions': ['v1'],
            'storage_version': 'v1',
            'conversion_strategy': 'None',
            'established': True,
            'names_accepted': True,
            'resource_count': 10,
            'issues': [],
            'healthy': True
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = crd_analyzer.print_results(results, 'plain', False, True)

        output = f.getvalue()
        # Verbose should show all details
        self.assertIn('Group:', output)
        self.assertIn('Kind:', output)
        self.assertIn('Scope:', output)
        self.assertIn('Versions:', output)


class TestGetCrds(unittest.TestCase):
    """Test get_crds function with mocking."""

    @patch('k8s_crd_health_analyzer.run_kubectl')
    def test_get_crds(self, mock_run):
        """Test getting CRDs."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'crd1.example.com'}},
                {'metadata': {'name': 'crd2.example.com'}}
            ]
        })

        crds = crd_analyzer.get_crds()

        self.assertEqual(len(crds['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('get', call_args)
        self.assertIn('crds', call_args)
        self.assertIn('-o', call_args)
        self.assertIn('json', call_args)


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
