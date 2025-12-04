#!/usr/bin/env python3
"""
Tests for k8s_daemonset_health_monitor.py

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

import k8s_daemonset_health_monitor as ds_health


def run_command(cmd_args, input_data=None):
    """Run the k8s_daemonset_health_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_daemonset_health_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sDaemonSetHealthMonitor(unittest.TestCase):
    """Test cases for k8s_daemonset_health_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('DaemonSet', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('DaemonSet', stdout)

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
        returncode, stdout, stderr = run_command(['--namespace', 'kube-system'])
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
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'kube-system'])
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
        with open('k8s_daemonset_health_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_daemonset_health_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('DaemonSet', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_daemonset_health_monitor.py', 'r') as f:
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
            'metadata': {'name': 'test-ds-abc123'},
            'spec': {'nodeName': 'node1'},
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

        issues, node_name = ds_health.check_pod_health(pod)

        self.assertEqual(len(issues), 0)
        self.assertEqual(node_name, 'node1')

    def test_pod_not_running(self):
        """Test pod in non-running phase."""
        pod = {
            'metadata': {'name': 'test-ds-abc123'},
            'spec': {'nodeName': 'node1'},
            'status': {
                'phase': 'Pending',
                'containerStatuses': [],
                'conditions': []
            }
        }

        issues, node_name = ds_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('Pending' in issue for issue in issues))

    def test_container_not_ready(self):
        """Test container not ready."""
        pod = {
            'metadata': {'name': 'test-ds-abc123'},
            'spec': {'nodeName': 'node1'},
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

        issues, node_name = ds_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('not ready' in issue for issue in issues))
        self.assertTrue(any('ImagePullBackOff' in issue for issue in issues))

    def test_container_high_restarts(self):
        """Test container with high restart count."""
        pod = {
            'metadata': {'name': 'test-ds-abc123'},
            'spec': {'nodeName': 'node2'},
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

        issues, node_name = ds_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('restarts' in issue for issue in issues))
        self.assertEqual(node_name, 'node2')

    def test_scheduling_issue(self):
        """Test pod with scheduling issue."""
        pod = {
            'metadata': {'name': 'test-ds-abc123'},
            'spec': {'nodeName': 'node1'},
            'status': {
                'phase': 'Pending',
                'containerStatuses': [],
                'conditions': [
                    {
                        'type': 'PodScheduled',
                        'status': 'False',
                        'reason': 'Unschedulable',
                        'message': 'Insufficient cpu'
                    }
                ]
            }
        }

        issues, node_name = ds_health.check_pod_health(pod)

        self.assertGreater(len(issues), 0)
        self.assertTrue(any('Scheduling issue' in issue for issue in issues))


class TestNodeMatchesSelector(unittest.TestCase):
    """Test node_matches_selector function."""

    def test_no_selector_matches_all(self):
        """Test that empty selector matches all nodes."""
        node = {
            'metadata': {
                'name': 'node1',
                'labels': {'kubernetes.io/hostname': 'node1'}
            }
        }

        self.assertTrue(ds_health.node_matches_selector(node, {}))
        self.assertTrue(ds_health.node_matches_selector(node, None))

    def test_matching_selector(self):
        """Test node that matches selector."""
        node = {
            'metadata': {
                'name': 'node1',
                'labels': {
                    'kubernetes.io/hostname': 'node1',
                    'node-role': 'worker',
                    'disk': 'ssd'
                }
            }
        }

        selector = {'node-role': 'worker', 'disk': 'ssd'}
        self.assertTrue(ds_health.node_matches_selector(node, selector))

    def test_non_matching_selector(self):
        """Test node that doesn't match selector."""
        node = {
            'metadata': {
                'name': 'node1',
                'labels': {
                    'kubernetes.io/hostname': 'node1',
                    'node-role': 'control-plane'
                }
            }
        }

        selector = {'node-role': 'worker'}
        self.assertFalse(ds_health.node_matches_selector(node, selector))

    def test_partial_match(self):
        """Test node with partial label match."""
        node = {
            'metadata': {
                'name': 'node1',
                'labels': {
                    'node-role': 'worker'
                }
            }
        }

        selector = {'node-role': 'worker', 'disk': 'ssd'}
        self.assertFalse(ds_health.node_matches_selector(node, selector))


class TestCheckDaemonSetHealth(unittest.TestCase):
    """Test check_daemonset_health function."""

    def test_healthy_daemonset(self):
        """Test status checking for healthy DaemonSet."""
        ds = {
            'metadata': {'name': 'test-ds', 'namespace': 'kube-system'},
            'spec': {
                'template': {
                    'spec': {
                        'nodeSelector': {}
                    }
                },
                'updateStrategy': {'type': 'RollingUpdate'}
            },
            'status': {
                'desiredNumberScheduled': 3,
                'currentNumberScheduled': 3,
                'numberReady': 3,
                'numberAvailable': 3,
                'updatedNumberScheduled': 3,
                'numberMisscheduled': 0
            }
        }

        # Create pods that match the nodes
        pods = {
            'items': [
                {
                    'metadata': {'name': 'test-ds-abc1'},
                    'spec': {'nodeName': 'node1'},
                    'status': {
                        'phase': 'Running',
                        'containerStatuses': [{'name': 'c1', 'ready': True, 'restartCount': 0, 'state': {'running': {}}}],
                        'conditions': [{'type': 'PodScheduled', 'status': 'True'}]
                    }
                },
                {
                    'metadata': {'name': 'test-ds-abc2'},
                    'spec': {'nodeName': 'node2'},
                    'status': {
                        'phase': 'Running',
                        'containerStatuses': [{'name': 'c1', 'ready': True, 'restartCount': 0, 'state': {'running': {}}}],
                        'conditions': [{'type': 'PodScheduled', 'status': 'True'}]
                    }
                },
                {
                    'metadata': {'name': 'test-ds-abc3'},
                    'spec': {'nodeName': 'node3'},
                    'status': {
                        'phase': 'Running',
                        'containerStatuses': [{'name': 'c1', 'ready': True, 'restartCount': 0, 'state': {'running': {}}}],
                        'conditions': [{'type': 'PodScheduled', 'status': 'True'}]
                    }
                }
            ]
        }

        nodes = {
            'items': [
                {
                    'metadata': {'name': 'node1', 'labels': {}},
                    'spec': {},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}
                },
                {
                    'metadata': {'name': 'node2', 'labels': {}},
                    'spec': {},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}
                },
                {
                    'metadata': {'name': 'node3', 'labels': {}},
                    'spec': {},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}
                }
            ]
        }

        is_healthy, issues, warnings, pod_issues, replicas = ds_health.check_daemonset_health(ds, pods, nodes)

        self.assertTrue(is_healthy)
        self.assertEqual(len(issues), 0)
        self.assertEqual(replicas['desired'], 3)
        self.assertEqual(replicas['ready'], 3)

    def test_daemonset_not_fully_scheduled(self):
        """Test DaemonSet with pods not scheduled on all nodes."""
        ds = {
            'metadata': {'name': 'test-ds', 'namespace': 'kube-system'},
            'spec': {
                'template': {
                    'spec': {
                        'nodeSelector': {}
                    }
                },
                'updateStrategy': {'type': 'RollingUpdate'}
            },
            'status': {
                'desiredNumberScheduled': 3,
                'currentNumberScheduled': 2,
                'numberReady': 2,
                'numberAvailable': 2,
                'updatedNumberScheduled': 2,
                'numberMisscheduled': 0
            }
        }

        pods = {'items': []}
        nodes = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = ds_health.check_daemonset_health(ds, pods, nodes)

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any('pods scheduled' in issue for issue in issues))

    def test_daemonset_not_ready(self):
        """Test DaemonSet with pods not ready."""
        ds = {
            'metadata': {'name': 'test-ds', 'namespace': 'kube-system'},
            'spec': {
                'template': {
                    'spec': {
                        'nodeSelector': {}
                    }
                },
                'updateStrategy': {'type': 'RollingUpdate'}
            },
            'status': {
                'desiredNumberScheduled': 3,
                'currentNumberScheduled': 3,
                'numberReady': 1,
                'numberAvailable': 1,
                'updatedNumberScheduled': 3,
                'numberMisscheduled': 0
            }
        }

        pods = {'items': []}
        nodes = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = ds_health.check_daemonset_health(ds, pods, nodes)

        self.assertFalse(is_healthy)
        self.assertTrue(any('pods ready' in issue for issue in issues))

    def test_daemonset_with_misscheduled_pods(self):
        """Test DaemonSet with misscheduled pods."""
        ds = {
            'metadata': {'name': 'test-ds', 'namespace': 'kube-system'},
            'spec': {
                'template': {
                    'spec': {
                        'nodeSelector': {}
                    }
                },
                'updateStrategy': {'type': 'RollingUpdate'}
            },
            'status': {
                'desiredNumberScheduled': 3,
                'currentNumberScheduled': 3,
                'numberReady': 3,
                'numberAvailable': 3,
                'updatedNumberScheduled': 3,
                'numberMisscheduled': 2
            }
        }

        pods = {'items': []}
        nodes = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = ds_health.check_daemonset_health(ds, pods, nodes)

        self.assertFalse(is_healthy)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any('running on nodes' in issue for issue in issues))

    def test_daemonset_rollout_in_progress(self):
        """Test DaemonSet with rollout in progress."""
        ds = {
            'metadata': {'name': 'test-ds', 'namespace': 'kube-system'},
            'spec': {
                'template': {
                    'spec': {
                        'nodeSelector': {}
                    }
                },
                'updateStrategy': {'type': 'RollingUpdate'}
            },
            'status': {
                'desiredNumberScheduled': 5,
                'currentNumberScheduled': 5,
                'numberReady': 5,
                'numberAvailable': 5,
                'updatedNumberScheduled': 3,
                'numberMisscheduled': 0
            }
        }

        pods = {'items': []}
        nodes = {'items': []}

        is_healthy, issues, warnings, pod_issues, replicas = ds_health.check_daemonset_health(ds, pods, nodes)

        self.assertGreater(len(warnings), 0)
        self.assertTrue(any('updated' in warning for warning in warnings))


class TestGetDaemonSets(unittest.TestCase):
    """Test get_daemonsets function with mocking."""

    @patch('k8s_daemonset_health_monitor.run_kubectl')
    def test_get_daemonsets_all_namespaces(self, mock_run):
        """Test getting DaemonSets from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'ds1', 'namespace': 'kube-system'}},
                {'metadata': {'name': 'ds2', 'namespace': 'default'}}
            ]
        })

        daemonsets = ds_health.get_daemonsets()

        self.assertEqual(len(daemonsets['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_daemonset_health_monitor.run_kubectl')
    def test_get_daemonsets_specific_namespace(self, mock_run):
        """Test getting DaemonSets from specific namespace."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'ds1', 'namespace': 'kube-system'}}
            ]
        })

        daemonsets = ds_health.get_daemonsets('kube-system')

        self.assertEqual(len(daemonsets['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('kube-system', call_args)


class TestPrintStatus(unittest.TestCase):
    """Test print_status function."""

    @patch('k8s_daemonset_health_monitor.get_pods_for_daemonset')
    def test_print_status_json_format(self, mock_get_pods):
        """Test print_status with JSON format."""
        mock_get_pods.return_value = {'items': []}

        daemonsets_data = {
            'items': [{
                'metadata': {'name': 'test-ds', 'namespace': 'kube-system'},
                'spec': {
                    'template': {'spec': {'nodeSelector': {}}},
                    'updateStrategy': {'type': 'RollingUpdate'}
                },
                'status': {
                    'desiredNumberScheduled': 3,
                    'currentNumberScheduled': 3,
                    'numberReady': 3,
                    'numberAvailable': 3,
                    'updatedNumberScheduled': 3,
                    'numberMisscheduled': 0
                }
            }]
        }

        nodes = {'items': []}

        # Capture stdout
        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = ds_health.print_status(daemonsets_data, nodes, 'json', False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'test-ds')

    @patch('k8s_daemonset_health_monitor.get_pods_for_daemonset')
    def test_print_status_plain_format(self, mock_get_pods):
        """Test print_status with plain format."""
        mock_get_pods.return_value = {'items': []}

        daemonsets_data = {
            'items': [{
                'metadata': {'name': 'test-ds', 'namespace': 'kube-system'},
                'spec': {
                    'template': {'spec': {'nodeSelector': {}}},
                    'updateStrategy': {'type': 'RollingUpdate'}
                },
                'status': {
                    'desiredNumberScheduled': 3,
                    'currentNumberScheduled': 3,
                    'numberReady': 3,
                    'numberAvailable': 3,
                    'updatedNumberScheduled': 3,
                    'numberMisscheduled': 0
                }
            }]
        }

        nodes = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = ds_health.print_status(daemonsets_data, nodes, 'plain', False)

        output = f.getvalue()
        self.assertIn('test-ds', output)
        self.assertIn('kube-system', output)

    @patch('k8s_daemonset_health_monitor.get_pods_for_daemonset')
    def test_print_status_warn_only(self, mock_get_pods):
        """Test print_status with warn_only flag."""
        mock_get_pods.return_value = {'items': []}

        daemonsets_data = {
            'items': [
                {
                    'metadata': {'name': 'healthy-ds', 'namespace': 'kube-system'},
                    'spec': {
                        'template': {'spec': {'nodeSelector': {}}},
                        'updateStrategy': {'type': 'RollingUpdate'}
                    },
                    'status': {
                        'desiredNumberScheduled': 3,
                        'currentNumberScheduled': 3,
                        'numberReady': 3,
                        'numberAvailable': 3,
                        'updatedNumberScheduled': 3,
                        'numberMisscheduled': 0
                    }
                },
                {
                    'metadata': {'name': 'unhealthy-ds', 'namespace': 'kube-system'},
                    'spec': {
                        'template': {'spec': {'nodeSelector': {}}},
                        'updateStrategy': {'type': 'RollingUpdate'}
                    },
                    'status': {
                        'desiredNumberScheduled': 3,
                        'currentNumberScheduled': 3,
                        'numberReady': 1,
                        'numberAvailable': 1,
                        'updatedNumberScheduled': 3,
                        'numberMisscheduled': 0
                    }
                }
            ]
        }

        nodes = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = ds_health.print_status(daemonsets_data, nodes, 'json', True)

        output = f.getvalue()
        data = json.loads(output)

        # Only unhealthy DaemonSet should be in output
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'unhealthy-ds')
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
