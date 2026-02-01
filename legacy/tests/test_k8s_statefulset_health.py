#!/usr/bin/env python3
"""
Tests for k8s_statefulset_health.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_statefulset_health as sts_health


def run_command(cmd_args, input_data=None):
    """Run the k8s_statefulset_health.py script with given arguments."""
    cmd = [sys.executable, 'k8s_statefulset_health.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sStatefulSetHealth(unittest.TestCase):
    """Test cases for k8s_statefulset_health.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('StatefulSet', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('StatefulSet', stdout)

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

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'kube-system'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'plain', '--warn-only', '--namespace', 'kube-system'])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
        # Error message should be helpful
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_statefulset_health.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_statefulset_health.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('StatefulSet', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_statefulset_health.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestCheckPodHealth(unittest.TestCase):
    """Test check_pod_health function."""

    def test_healthy_pod(self):
        """Test status checking for healthy pod."""
        pod = {
            'metadata': {'name': 'test-pod-0'},
            'status': {
                'phase': 'Running',
                'containerStatuses': [
                    {
                        'name': 'container1',
                        'ready': True,
                        'restartCount': 0,
                        'state': {'running': {}}
                    }
                ],
                'conditions': [
                    {'type': 'PodScheduled', 'status': 'True'}
                ]
            }
        }

        issues = sts_health.check_pod_health(pod)

        self.assertEqual(len(issues), 0)

    def test_pod_not_running(self):
        """Test pod in non-running phase."""
        pod = {
            'metadata': {'name': 'test-pod-0'},
            'status': {
                'phase': 'Pending',
                'containerStatuses': [],
                'conditions': []
            }
        }

        issues = sts_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('Pending' in issue for issue in issues))

    def test_container_not_ready(self):
        """Test container not ready."""
        pod = {
            'metadata': {'name': 'test-pod-0'},
            'status': {
                'phase': 'Running',
                'containerStatuses': [
                    {
                        'name': 'container1',
                        'ready': False,
                        'restartCount': 0,
                        'state': {
                            'waiting': {
                                'reason': 'ImagePullBackOff',
                                'message': 'Failed to pull image'
                            }
                        }
                    }
                ],
                'conditions': []
            }
        }

        issues = sts_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('not ready' in issue for issue in issues))
        self.assertTrue(any('ImagePullBackOff' in issue for issue in issues))

    def test_container_high_restarts(self):
        """Test container with high restart count."""
        pod = {
            'metadata': {'name': 'test-pod-0'},
            'status': {
                'phase': 'Running',
                'containerStatuses': [
                    {
                        'name': 'container1',
                        'ready': True,
                        'restartCount': 10,
                        'state': {'running': {}}
                    }
                ],
                'conditions': []
            }
        }

        issues = sts_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('restarts' in issue for issue in issues))

    def test_volume_binding_issue(self):
        """Test pod with volume binding issue."""
        pod = {
            'metadata': {'name': 'test-pod-0'},
            'status': {
                'phase': 'Pending',
                'containerStatuses': [],
                'conditions': [
                    {
                        'type': 'PodScheduled',
                        'status': 'False',
                        'reason': 'Unschedulable',
                        'message': 'persistentvolumeclaim "pvc-test" not found'
                    }
                ]
            }
        }

        issues = sts_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('volume' in issue.lower() or 'pvc' in issue.lower() for issue in issues))


class TestCheckStatefulSetHealth(unittest.TestCase):
    """Test check_statefulset_health function."""

    def test_healthy_statefulset(self):
        """Test status checking for healthy StatefulSet."""
        sts = {
            'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 3},
            'spec': {
                'replicas': 3,
                'updateStrategy': {'type': 'RollingUpdate'},
                'volumeClaimTemplates': []
            },
            'status': {
                'readyReplicas': 3,
                'updatedReplicas': 3,
                'currentReplicas': 3,
                'observedGeneration': 3,
                'conditions': []
            }
        }

        pods = {'items': []}
        pvcs = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = sts_health.check_statefulset_health(sts, pods, pvcs)

        self.assertTrue(is_healthy)
        self.assertEqual(len(issues), 0)
        self.assertEqual(replicas['desired'], 3)
        self.assertEqual(replicas['ready'], 3)

    def test_statefulset_not_ready(self):
        """Test StatefulSet with pods not ready."""
        sts = {
            'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 3},
            'spec': {
                'replicas': 3,
                'updateStrategy': {'type': 'RollingUpdate'},
                'volumeClaimTemplates': []
            },
            'status': {
                'readyReplicas': 1,
                'updatedReplicas': 3,
                'currentReplicas': 3,
                'observedGeneration': 3,
                'conditions': []
            }
        }

        pods = {'items': []}
        pvcs = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = sts_health.check_statefulset_health(sts, pods, pvcs)

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any('replicas ready' in issue for issue in issues))

    def test_statefulset_with_partition(self):
        """Test StatefulSet with partition rollout."""
        sts = {
            'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 3},
            'spec': {
                'replicas': 5,
                'updateStrategy': {
                    'type': 'RollingUpdate',
                    'rollingUpdate': {'partition': 2}
                },
                'volumeClaimTemplates': []
            },
            'status': {
                'readyReplicas': 5,
                'updatedReplicas': 3,
                'currentReplicas': 5,
                'observedGeneration': 3,
                'conditions': []
            }
        }

        pods = {'items': []}
        pvcs = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = sts_health.check_statefulset_health(sts, pods, pvcs)

        self.assertGreater(len(warnings), 0)
        self.assertTrue(any('Partition' in warning for warning in warnings))

    def test_statefulset_generation_not_observed(self):
        """Test StatefulSet with generation not observed."""
        sts = {
            'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 5},
            'spec': {
                'replicas': 3,
                'updateStrategy': {'type': 'RollingUpdate'},
                'volumeClaimTemplates': []
            },
            'status': {
                'readyReplicas': 3,
                'updatedReplicas': 3,
                'currentReplicas': 3,
                'observedGeneration': 4,
                'conditions': []
            }
        }

        pods = {'items': []}
        pvcs = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = sts_health.check_statefulset_health(sts, pods, pvcs)

        self.assertFalse(is_healthy)
        self.assertTrue(any('generation not yet observed' in issue for issue in issues))

    def test_statefulset_with_missing_pvc(self):
        """Test StatefulSet with missing PVC."""
        sts = {
            'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 3},
            'spec': {
                'replicas': 2,
                'updateStrategy': {'type': 'RollingUpdate'},
                'volumeClaimTemplates': [
                    {
                        'metadata': {'name': 'data'},
                        'spec': {'storageClassName': 'standard'}
                    }
                ]
            },
            'status': {
                'readyReplicas': 2,
                'updatedReplicas': 2,
                'currentReplicas': 2,
                'observedGeneration': 3,
                'conditions': []
            }
        }

        pods = {'items': []}
        pvcs = {'items': []}  # No PVCs exist

        is_healthy, issues, warnings, pod_issues, replicas = sts_health.check_statefulset_health(sts, pods, pvcs)

        self.assertFalse(is_healthy)
        self.assertTrue(any('Missing PVC' in issue for issue in issues))

    def test_statefulset_with_unbound_pvc(self):
        """Test StatefulSet with unbound PVC."""
        sts = {
            'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 3},
            'spec': {
                'replicas': 1,
                'updateStrategy': {'type': 'RollingUpdate'},
                'volumeClaimTemplates': [
                    {
                        'metadata': {'name': 'data'},
                        'spec': {'storageClassName': 'standard'}
                    }
                ]
            },
            'status': {
                'readyReplicas': 1,
                'updatedReplicas': 1,
                'currentReplicas': 1,
                'observedGeneration': 3,
                'conditions': []
            }
        }

        pods = {'items': []}
        pvcs = {
            'items': [
                {
                    'metadata': {'name': 'data-test-sts-0'},
                    'status': {'phase': 'Pending'}
                }
            ]
        }

        is_healthy, issues, warnings, pod_issues, replicas = sts_health.check_statefulset_health(sts, pods, pvcs)

        self.assertFalse(is_healthy)
        self.assertTrue(any('not bound' in issue for issue in issues))


class TestGetStatefulSets(unittest.TestCase):
    """Test get_statefulsets function with mocking."""

    @patch('k8s_statefulset_health.run_kubectl')
    def test_get_statefulsets_all_namespaces(self, mock_run):
        """Test getting StatefulSets from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'sts1', 'namespace': 'default'}},
                {'metadata': {'name': 'sts2', 'namespace': 'production'}}
            ]
        })

        statefulsets = sts_health.get_statefulsets()

        self.assertEqual(len(statefulsets['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_statefulset_health.run_kubectl')
    def test_get_statefulsets_specific_namespace(self, mock_run):
        """Test getting StatefulSets from specific namespace."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'sts1', 'namespace': 'production'}}
            ]
        })

        statefulsets = sts_health.get_statefulsets('production')

        self.assertEqual(len(statefulsets['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)


class TestPrintStatus(unittest.TestCase):
    """Test print_status function."""

    @patch('k8s_statefulset_health.get_pods_for_statefulset')
    @patch('k8s_statefulset_health.get_pvcs_for_namespace')
    def test_print_status_json_format(self, mock_get_pvcs, mock_get_pods):
        """Test print_status with JSON format."""
        mock_get_pods.return_value = {'items': []}
        mock_get_pvcs.return_value = {'items': []}

        statefulsets_data = {
            'items': [{
                'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 1},
                'spec': {
                    'replicas': 3,
                    'updateStrategy': {'type': 'RollingUpdate'},
                    'volumeClaimTemplates': []
                },
                'status': {
                    'readyReplicas': 3,
                    'updatedReplicas': 3,
                    'currentReplicas': 3,
                    'observedGeneration': 1,
                    'conditions': []
                }
            }]
        }

        # Capture stdout
        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = sts_health.print_status(statefulsets_data, 'json', False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'test-sts')

    @patch('k8s_statefulset_health.get_pods_for_statefulset')
    @patch('k8s_statefulset_health.get_pvcs_for_namespace')
    def test_print_status_plain_format(self, mock_get_pvcs, mock_get_pods):
        """Test print_status with plain format."""
        mock_get_pods.return_value = {'items': []}
        mock_get_pvcs.return_value = {'items': []}

        statefulsets_data = {
            'items': [{
                'metadata': {'name': 'test-sts', 'namespace': 'default', 'generation': 1},
                'spec': {
                    'replicas': 3,
                    'updateStrategy': {'type': 'RollingUpdate'},
                    'volumeClaimTemplates': []
                },
                'status': {
                    'readyReplicas': 3,
                    'updatedReplicas': 3,
                    'currentReplicas': 3,
                    'observedGeneration': 1,
                    'conditions': []
                }
            }]
        }

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = sts_health.print_status(statefulsets_data, 'plain', False)

        output = f.getvalue()
        self.assertIn('test-sts', output)
        self.assertIn('default', output)

    @patch('k8s_statefulset_health.get_pods_for_statefulset')
    @patch('k8s_statefulset_health.get_pvcs_for_namespace')
    def test_print_status_warn_only(self, mock_get_pvcs, mock_get_pods):
        """Test print_status with warn_only flag."""
        mock_get_pods.return_value = {'items': []}
        mock_get_pvcs.return_value = {'items': []}

        statefulsets_data = {
            'items': [
                {
                    'metadata': {'name': 'healthy-sts', 'namespace': 'default', 'generation': 1},
                    'spec': {
                        'replicas': 3,
                        'updateStrategy': {'type': 'RollingUpdate'},
                        'volumeClaimTemplates': []
                    },
                    'status': {
                        'readyReplicas': 3,
                        'updatedReplicas': 3,
                        'currentReplicas': 3,
                        'observedGeneration': 1,
                        'conditions': []
                    }
                },
                {
                    'metadata': {'name': 'unhealthy-sts', 'namespace': 'default', 'generation': 1},
                    'spec': {
                        'replicas': 3,
                        'updateStrategy': {'type': 'RollingUpdate'},
                        'volumeClaimTemplates': []
                    },
                    'status': {
                        'readyReplicas': 1,
                        'updatedReplicas': 1,
                        'currentReplicas': 1,
                        'observedGeneration': 1,
                        'conditions': []
                    }
                }
            ]
        }

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = sts_health.print_status(statefulsets_data, 'json', True)

        output = f.getvalue()
        data = json.loads(output)

        # Only unhealthy StatefulSet should be in output
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'unhealthy-sts')
        self.assertTrue(has_issues)


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
