#!/usr/bin/env python3
"""
Tests for k8s_gitops_sync_monitor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster
or GitOps controllers (Flux CD/ArgoCD). Tests cover argument parsing, help messages,
error handling, and core status-checking functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_gitops_sync_monitor as gitops_monitor


def run_command(cmd_args, input_data=None):
    """Run the k8s_gitops_sync_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_gitops_sync_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sGitopsSyncMonitor(unittest.TestCase):
    """Test cases for k8s_gitops_sync_monitor.py CLI."""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('GitOps', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Flux', stdout)
        self.assertIn('ArgoCD', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('GitOps', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl) or 0/1 (kubectl present but no resources)
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_short(self):
        """Test -f short option works."""
        returncode, stdout, stderr = run_command(['-f', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_invalid_format(self):
        """Test that invalid format values are rejected."""
        returncode, stdout, stderr = run_command(['--format', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid choice', stderr)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'flux-system'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'argocd'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'flux-system'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'plain', '--warn-only', '--namespace', 'argocd'])
        self.assertIn(returncode, [0, 1, 2])

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will check for kubectl, then query cluster)
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_gitops_sync_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_gitops_sync_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('GitOps', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_gitops_sync_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_script_documents_exit_codes(self):
        """Test that script documents exit codes."""
        with open('k8s_gitops_sync_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)


class TestCheckFluxKustomization(unittest.TestCase):
    """Test check_flux_kustomization function."""

    def test_healthy_kustomization(self):
        """Test status checking for healthy Flux Kustomization."""
        resource = {
            'metadata': {'name': 'flux-system', 'namespace': 'flux-system'},
            'spec': {'sourceRef': {'name': 'flux-system'}, 'suspend': False},
            'status': {
                'lastAppliedRevision': 'main@sha1:abc123def456',
                'lastAttemptedRevision': 'main@sha1:abc123def456',
                'conditions': [
                    {'type': 'Ready', 'status': 'True', 'reason': 'ReconciliationSucceeded'}
                ]
            }
        }

        result = gitops_monitor.check_flux_kustomization(resource)

        self.assertTrue(result['healthy'])
        self.assertEqual(len(result['issues']), 0)
        self.assertEqual(result['type'], 'Kustomization')
        self.assertEqual(result['controller'], 'flux')
        self.assertEqual(result['name'], 'flux-system')

    def test_unhealthy_kustomization_not_ready(self):
        """Test status checking for Kustomization not ready."""
        resource = {
            'metadata': {'name': 'app', 'namespace': 'flux-system'},
            'spec': {'sourceRef': {'name': 'app-repo'}, 'suspend': False},
            'status': {
                'conditions': [
                    {'type': 'Ready', 'status': 'False', 'reason': 'ReconciliationFailed', 'message': 'kustomize build failed'}
                ]
            }
        }

        result = gitops_monitor.check_flux_kustomization(resource)

        self.assertFalse(result['healthy'])
        self.assertGreater(len(result['issues']), 0)
        self.assertTrue(any('Not ready' in issue for issue in result['issues']))

    def test_suspended_kustomization(self):
        """Test status checking for suspended Kustomization."""
        resource = {
            'metadata': {'name': 'suspended-app', 'namespace': 'flux-system'},
            'spec': {'sourceRef': {'name': 'repo'}, 'suspend': True},
            'status': {
                'conditions': [
                    {'type': 'Ready', 'status': 'True'}
                ]
            }
        }

        result = gitops_monitor.check_flux_kustomization(resource)

        self.assertFalse(result['healthy'])
        self.assertTrue(result['suspended'])
        self.assertTrue(any('suspended' in issue.lower() for issue in result['issues']))

    def test_kustomization_revision_mismatch(self):
        """Test Kustomization with revision mismatch."""
        resource = {
            'metadata': {'name': 'app', 'namespace': 'flux-system'},
            'spec': {'sourceRef': {'name': 'repo'}, 'suspend': False},
            'status': {
                'lastAppliedRevision': 'main@sha1:oldrevision1',
                'lastAttemptedRevision': 'main@sha1:newrevision2',
                'conditions': [
                    {'type': 'Ready', 'status': 'True'}
                ]
            }
        }

        result = gitops_monitor.check_flux_kustomization(resource)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('Revision mismatch' in issue for issue in result['issues']))


class TestCheckFluxHelmRelease(unittest.TestCase):
    """Test check_flux_helmrelease function."""

    def test_healthy_helmrelease(self):
        """Test status checking for healthy HelmRelease."""
        resource = {
            'metadata': {'name': 'nginx', 'namespace': 'default'},
            'spec': {
                'chart': {'spec': {'name': 'nginx'}},
                'suspend': False
            },
            'status': {
                'lastAppliedRevision': '1.0.0',
                'conditions': [
                    {'type': 'Ready', 'status': 'True'},
                    {'type': 'Released', 'status': 'True'}
                ]
            }
        }

        result = gitops_monitor.check_flux_helmrelease(resource)

        self.assertTrue(result['healthy'])
        self.assertEqual(len(result['issues']), 0)
        self.assertEqual(result['type'], 'HelmRelease')
        self.assertEqual(result['controller'], 'flux')

    def test_unhealthy_helmrelease_not_released(self):
        """Test HelmRelease that failed to release."""
        resource = {
            'metadata': {'name': 'broken-chart', 'namespace': 'default'},
            'spec': {
                'chart': {'spec': {'name': 'broken'}},
                'suspend': False
            },
            'status': {
                'conditions': [
                    {'type': 'Ready', 'status': 'False', 'reason': 'InstallFailed'},
                    {'type': 'Released', 'status': 'False', 'reason': 'InstallFailed'}
                ],
                'failures': 3
            }
        }

        result = gitops_monitor.check_flux_helmrelease(resource)

        self.assertFalse(result['healthy'])
        self.assertGreater(len(result['issues']), 0)


class TestCheckFluxGitRepository(unittest.TestCase):
    """Test check_flux_gitrepository function."""

    def test_healthy_gitrepository(self):
        """Test status checking for healthy GitRepository."""
        resource = {
            'metadata': {'name': 'flux-system', 'namespace': 'flux-system'},
            'spec': {
                'url': 'https://github.com/org/repo',
                'ref': {'branch': 'main'},
                'suspend': False
            },
            'status': {
                'artifact': {'revision': 'main@sha1:abc123'},
                'conditions': [
                    {'type': 'Ready', 'status': 'True'}
                ]
            }
        }

        result = gitops_monitor.check_flux_gitrepository(resource)

        self.assertTrue(result['healthy'])
        self.assertEqual(len(result['issues']), 0)
        self.assertEqual(result['type'], 'GitRepository')
        self.assertIn('github.com', result['url'])

    def test_gitrepository_fetch_failed(self):
        """Test GitRepository with fetch failure."""
        resource = {
            'metadata': {'name': 'broken-repo', 'namespace': 'flux-system'},
            'spec': {
                'url': 'https://github.com/org/private-repo',
                'ref': {'branch': 'main'},
                'suspend': False
            },
            'status': {
                'conditions': [
                    {'type': 'Ready', 'status': 'False', 'reason': 'AuthenticationFailed'},
                    {'type': 'FetchFailed', 'status': 'True', 'message': 'authentication required'}
                ]
            }
        }

        result = gitops_monitor.check_flux_gitrepository(resource)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('Fetch failed' in issue or 'Not ready' in issue for issue in result['issues']))


class TestCheckArgoCDApplication(unittest.TestCase):
    """Test check_argocd_application function."""

    def test_healthy_application(self):
        """Test status checking for healthy ArgoCD Application."""
        resource = {
            'metadata': {'name': 'my-app', 'namespace': 'argocd'},
            'spec': {
                'source': {
                    'repoURL': 'https://github.com/org/repo',
                    'targetRevision': 'HEAD'
                },
                'destination': {'namespace': 'production'}
            },
            'status': {
                'sync': {'status': 'Synced'},
                'health': {'status': 'Healthy'},
                'conditions': []
            }
        }

        result = gitops_monitor.check_argocd_application(resource)

        self.assertTrue(result['healthy'])
        self.assertEqual(len(result['issues']), 0)
        self.assertEqual(result['type'], 'Application')
        self.assertEqual(result['controller'], 'argocd')
        self.assertEqual(result['sync_status'], 'Synced')
        self.assertEqual(result['health_status'], 'Healthy')

    def test_application_out_of_sync(self):
        """Test ArgoCD Application that is out of sync."""
        resource = {
            'metadata': {'name': 'out-of-sync-app', 'namespace': 'argocd'},
            'spec': {
                'source': {'repoURL': 'https://github.com/org/repo'},
                'destination': {'namespace': 'production'}
            },
            'status': {
                'sync': {'status': 'OutOfSync'},
                'health': {'status': 'Healthy'},
                'conditions': []
            }
        }

        result = gitops_monitor.check_argocd_application(resource)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('OutOfSync' in issue for issue in result['issues']))

    def test_application_degraded_health(self):
        """Test ArgoCD Application with degraded health."""
        resource = {
            'metadata': {'name': 'unhealthy-app', 'namespace': 'argocd'},
            'spec': {
                'source': {'repoURL': 'https://github.com/org/repo'},
                'destination': {'namespace': 'production'}
            },
            'status': {
                'sync': {'status': 'Synced'},
                'health': {'status': 'Degraded'},
                'conditions': []
            }
        }

        result = gitops_monitor.check_argocd_application(resource)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('Degraded' in issue for issue in result['issues']))

    def test_application_sync_failed(self):
        """Test ArgoCD Application with failed sync operation."""
        resource = {
            'metadata': {'name': 'failed-app', 'namespace': 'argocd'},
            'spec': {
                'source': {'repoURL': 'https://github.com/org/repo'},
                'destination': {'namespace': 'production'}
            },
            'status': {
                'sync': {'status': 'OutOfSync'},
                'health': {'status': 'Missing'},
                'operationState': {
                    'phase': 'Failed',
                    'message': 'one or more synchronization tasks are not valid'
                },
                'conditions': []
            }
        }

        result = gitops_monitor.check_argocd_application(resource)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('Failed' in issue for issue in result['issues']))


class TestCheckArgoCDApplicationSet(unittest.TestCase):
    """Test check_argocd_applicationset function."""

    def test_healthy_applicationset(self):
        """Test status checking for healthy ApplicationSet."""
        resource = {
            'metadata': {'name': 'my-appset', 'namespace': 'argocd'},
            'status': {
                'conditions': [
                    {'type': 'ResourcesUpToDate', 'status': 'True'}
                ]
            }
        }

        result = gitops_monitor.check_argocd_applicationset(resource)

        self.assertTrue(result['healthy'])
        self.assertEqual(len(result['issues']), 0)
        self.assertEqual(result['type'], 'ApplicationSet')

    def test_applicationset_with_error(self):
        """Test ApplicationSet with error condition."""
        resource = {
            'metadata': {'name': 'broken-appset', 'namespace': 'argocd'},
            'status': {
                'conditions': [
                    {'type': 'ErrorOccurred', 'status': 'True', 'message': 'generator error'}
                ]
            }
        }

        result = gitops_monitor.check_argocd_applicationset(resource)

        self.assertFalse(result['healthy'])
        self.assertTrue(any('Error' in issue for issue in result['issues']))


class TestGetCondition(unittest.TestCase):
    """Test get_condition helper function."""

    def test_get_existing_condition(self):
        """Test getting an existing condition."""
        conditions = [
            {'type': 'Ready', 'status': 'True'},
            {'type': 'Healthy', 'status': 'False'}
        ]

        result = gitops_monitor.get_condition(conditions, 'Ready')

        self.assertIsNotNone(result)
        self.assertEqual(result['status'], 'True')

    def test_get_nonexistent_condition(self):
        """Test getting a condition that doesn't exist."""
        conditions = [
            {'type': 'Ready', 'status': 'True'}
        ]

        result = gitops_monitor.get_condition(conditions, 'NotFound')

        self.assertIsNone(result)

    def test_get_condition_empty_list(self):
        """Test getting a condition from empty list."""
        result = gitops_monitor.get_condition([], 'Ready')
        self.assertIsNone(result)

    def test_get_condition_none(self):
        """Test getting a condition from None."""
        result = gitops_monitor.get_condition(None, 'Ready')
        self.assertIsNone(result)


class TestParseTime(unittest.TestCase):
    """Test parse_time helper function."""

    def test_parse_valid_time(self):
        """Test parsing valid Kubernetes timestamp."""
        result = gitops_monitor.parse_time('2024-01-15T10:30:00Z')
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_parse_empty_time(self):
        """Test parsing empty string."""
        result = gitops_monitor.parse_time('')
        self.assertIsNone(result)

    def test_parse_none_time(self):
        """Test parsing None."""
        result = gitops_monitor.parse_time(None)
        self.assertIsNone(result)

    def test_parse_invalid_time(self):
        """Test parsing invalid timestamp."""
        result = gitops_monitor.parse_time('not-a-timestamp')
        self.assertIsNone(result)


class TestPrintResults(unittest.TestCase):
    """Test print_results function."""

    def test_print_results_json_format(self):
        """Test print_results with JSON format."""
        results = [{
            'type': 'Kustomization',
            'controller': 'flux',
            'namespace': 'flux-system',
            'name': 'test',
            'healthy': True,
            'suspended': False,
            'source': 'test-repo',
            'revision': 'abc123',
            'issues': []
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = gitops_monitor.print_results(results, 'json', False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)

    def test_print_results_plain_format(self):
        """Test print_results with plain format."""
        results = [{
            'type': 'Kustomization',
            'controller': 'flux',
            'namespace': 'flux-system',
            'name': 'test',
            'healthy': True,
            'suspended': False,
            'source': 'test-repo',
            'revision': 'abc123',
            'issues': []
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = gitops_monitor.print_results(results, 'plain', False)

        output = f.getvalue()
        self.assertIn('Flux CD', output)
        self.assertIn('test', output)

    def test_print_results_warn_only(self):
        """Test print_results with warn_only flag."""
        results = [
            {
                'type': 'Kustomization',
                'controller': 'flux',
                'namespace': 'flux-system',
                'name': 'healthy',
                'healthy': True,
                'suspended': False,
                'issues': []
            },
            {
                'type': 'Kustomization',
                'controller': 'flux',
                'namespace': 'flux-system',
                'name': 'unhealthy',
                'healthy': False,
                'suspended': False,
                'issues': ['Some error']
            }
        ]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = gitops_monitor.print_results(results, 'json', True)

        output = f.getvalue()
        data = json.loads(output)

        # Only unhealthy resource should be in output
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'unhealthy')
        self.assertTrue(has_issues)

    def test_print_results_empty(self):
        """Test print_results with no resources."""
        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = gitops_monitor.print_results([], 'plain', False)

        output = f.getvalue()
        self.assertIn('No GitOps resources found', output)
        self.assertFalse(has_issues)


class TestGetResource(unittest.TestCase):
    """Test get_resource function with mocking."""

    @patch('k8s_gitops_sync_monitor.run_kubectl')
    def test_get_resource_success(self, mock_run):
        """Test successful resource retrieval."""
        mock_run.return_value = (0, json.dumps({
            'items': [{'metadata': {'name': 'test'}}]
        }), '')

        result = gitops_monitor.get_resource('kustomizations', None, 'kustomize.toolkit.fluxcd.io')

        self.assertEqual(len(result['items']), 1)

    @patch('k8s_gitops_sync_monitor.run_kubectl')
    def test_get_resource_not_found(self, mock_run):
        """Test resource type not found (no CRD installed)."""
        mock_run.return_value = (1, '', 'the server doesn\'t have a resource type')

        result = gitops_monitor.get_resource('kustomizations', None, 'kustomize.toolkit.fluxcd.io')

        self.assertEqual(len(result['items']), 0)


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
