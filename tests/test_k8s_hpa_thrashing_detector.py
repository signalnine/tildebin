#!/usr/bin/env python3
"""
Tests for k8s_hpa_thrashing_detector.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import os
from datetime import datetime, timezone, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_hpa_thrashing_detector as hpa_detector


def run_command(cmd_args, input_data=None):
    """Run the k8s_hpa_thrashing_detector.py script with given arguments."""
    cmd = [sys.executable, 'k8s_hpa_thrashing_detector.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sHpaThrashingDetector(unittest.TestCase):
    """Test cases for k8s_hpa_thrashing_detector.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('thrashing', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--window', stdout)
        self.assertIn('--threshold', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('HPA', stdout)

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

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [1, 2])

    def test_window_option(self):
        """Test --window option is accepted."""
        returncode, stdout, stderr = run_command(['--window', '60'])
        self.assertIn(returncode, [1, 2])

    def test_threshold_option(self):
        """Test --threshold option is accepted."""
        returncode, stdout, stderr = run_command(['--threshold', '6'])
        self.assertIn(returncode, [1, 2])

    def test_invalid_window(self):
        """Test that invalid window values are rejected."""
        returncode, stdout, stderr = run_command(['--window', '0'])
        self.assertEqual(returncode, 2)
        self.assertIn('at least 1', stderr)

    def test_invalid_threshold(self):
        """Test that invalid threshold values are rejected."""
        returncode, stdout, stderr = run_command(['--threshold', '1'])
        self.assertEqual(returncode, 2)
        self.assertIn('at least 2', stderr)

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command([
            '-f', 'json', '-w', '-n', 'default', '--window', '45', '--threshold', '5'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        self.assertNotEqual(returncode, 0)
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_hpa_thrashing_detector.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_hpa_thrashing_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('"""', content)
        self.assertIn('thrashing', content[:1000].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_hpa_thrashing_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestCheckHpaStatus(unittest.TestCase):
    """Test check_hpa_status function."""

    def test_healthy_hpa(self):
        """Test status checking for healthy HPA."""
        hpa = {
            'metadata': {'name': 'test-hpa', 'namespace': 'default'},
            'spec': {'minReplicas': 2, 'maxReplicas': 10},
            'status': {
                'currentReplicas': 4,
                'desiredReplicas': 4,
                'conditions': [
                    {'type': 'ScalingActive', 'status': 'True'},
                    {'type': 'AbleToScale', 'status': 'True'}
                ],
                'currentMetrics': [
                    {'type': 'Resource', 'resource': {'name': 'cpu'}}
                ]
            }
        }

        result = hpa_detector.check_hpa_status(hpa)

        self.assertEqual(result['name'], 'test-hpa')
        self.assertEqual(result['namespace'], 'default')
        self.assertEqual(result['min_replicas'], 2)
        self.assertEqual(result['max_replicas'], 10)
        self.assertEqual(result['current_replicas'], 4)
        self.assertEqual(len(result['issues']), 0)

    def test_hpa_at_max_replicas(self):
        """Test HPA at maximum replicas."""
        hpa = {
            'metadata': {'name': 'maxed-hpa', 'namespace': 'production'},
            'spec': {'minReplicas': 1, 'maxReplicas': 10},
            'status': {
                'currentReplicas': 10,
                'desiredReplicas': 10,
                'conditions': [],
                'currentMetrics': [{'type': 'Resource'}]
            }
        }

        result = hpa_detector.check_hpa_status(hpa)

        self.assertTrue(any('at_max' in issue['type'] for issue in result['issues']))

    def test_hpa_scaling_inactive(self):
        """Test HPA with scaling inactive."""
        hpa = {
            'metadata': {'name': 'inactive-hpa', 'namespace': 'default'},
            'spec': {'minReplicas': 1, 'maxReplicas': 5},
            'status': {
                'currentReplicas': 1,
                'desiredReplicas': 1,
                'conditions': [
                    {
                        'type': 'ScalingActive',
                        'status': 'False',
                        'reason': 'FailedGetMetrics',
                        'message': 'Unable to fetch metrics'
                    }
                ],
                'currentMetrics': []
            }
        }

        result = hpa_detector.check_hpa_status(hpa)

        self.assertTrue(any('scaling_inactive' in issue['type'] for issue in result['issues']))

    def test_hpa_no_metrics(self):
        """Test HPA with no metrics available."""
        hpa = {
            'metadata': {'name': 'no-metrics-hpa', 'namespace': 'default'},
            'spec': {'minReplicas': 1, 'maxReplicas': 5},
            'status': {
                'currentReplicas': 1,
                'desiredReplicas': 1,
                'conditions': [],
                'currentMetrics': []
            }
        }

        result = hpa_detector.check_hpa_status(hpa)

        self.assertTrue(any('no_metrics' in issue['type'] for issue in result['issues']))

    def test_hpa_unable_to_scale(self):
        """Test HPA unable to scale."""
        hpa = {
            'metadata': {'name': 'stuck-hpa', 'namespace': 'default'},
            'spec': {'minReplicas': 1, 'maxReplicas': 5},
            'status': {
                'currentReplicas': 1,
                'desiredReplicas': 3,
                'conditions': [
                    {
                        'type': 'AbleToScale',
                        'status': 'False',
                        'reason': 'FailedGetScale',
                        'message': 'Cannot get scale'
                    }
                ],
                'currentMetrics': [{'type': 'Resource'}]
            }
        }

        result = hpa_detector.check_hpa_status(hpa)

        self.assertTrue(any('unable_to_scale' in issue['type'] for issue in result['issues']))


class TestDetectThrashing(unittest.TestCase):
    """Test detect_thrashing function."""

    def test_no_events(self):
        """Test thrashing detection with no events."""
        is_thrashing, count, events = hpa_detector.detect_thrashing([], 30, 4)

        self.assertFalse(is_thrashing)
        self.assertEqual(count, 0)
        self.assertEqual(len(events), 0)

    def test_few_events_no_thrashing(self):
        """Test thrashing detection with few events."""
        now = datetime.now(timezone.utc)
        events = [
            {'time': now - timedelta(minutes=10), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=20), 'reason': 'SuccessfulRescale', 'count': 1},
        ]

        is_thrashing, count, recent = hpa_detector.detect_thrashing(events, 30, 4)

        self.assertFalse(is_thrashing)
        self.assertEqual(count, 2)

    def test_many_events_thrashing(self):
        """Test thrashing detection with many events."""
        now = datetime.now(timezone.utc)
        events = [
            {'time': now - timedelta(minutes=5), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=10), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=15), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=20), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=25), 'reason': 'SuccessfulRescale', 'count': 1},
        ]

        is_thrashing, count, recent = hpa_detector.detect_thrashing(events, 30, 4)

        self.assertTrue(is_thrashing)
        self.assertEqual(count, 5)

    def test_old_events_ignored(self):
        """Test that events outside window are ignored."""
        now = datetime.now(timezone.utc)
        events = [
            {'time': now - timedelta(minutes=60), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=70), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=80), 'reason': 'SuccessfulRescale', 'count': 1},
            {'time': now - timedelta(minutes=90), 'reason': 'SuccessfulRescale', 'count': 1},
        ]

        is_thrashing, count, recent = hpa_detector.detect_thrashing(events, 30, 4)

        self.assertFalse(is_thrashing)
        self.assertEqual(count, 0)

    def test_event_count_aggregation(self):
        """Test that event counts are aggregated."""
        now = datetime.now(timezone.utc)
        events = [
            {'time': now - timedelta(minutes=5), 'reason': 'SuccessfulRescale', 'count': 3},
            {'time': now - timedelta(minutes=10), 'reason': 'SuccessfulRescale', 'count': 2},
        ]

        is_thrashing, count, recent = hpa_detector.detect_thrashing(events, 30, 4)

        self.assertTrue(is_thrashing)
        self.assertEqual(count, 5)


class TestAnalyzeHpaEvents(unittest.TestCase):
    """Test analyze_hpa_events function."""

    def test_filter_hpa_events(self):
        """Test that only HPA events are included."""
        events = {
            'items': [
                {
                    'involvedObject': {'kind': 'HorizontalPodAutoscaler', 'name': 'my-hpa'},
                    'metadata': {'namespace': 'default'},
                    'reason': 'SuccessfulRescale',
                    'message': 'Scaled to 5',
                    'lastTimestamp': '2024-01-15T10:00:00Z',
                    'count': 1
                },
                {
                    'involvedObject': {'kind': 'Pod', 'name': 'my-pod'},
                    'metadata': {'namespace': 'default'},
                    'reason': 'Created',
                    'message': 'Created container',
                    'lastTimestamp': '2024-01-15T10:00:00Z'
                },
                {
                    'involvedObject': {'kind': 'HorizontalPodAutoscaler', 'name': 'other-hpa'},
                    'metadata': {'namespace': 'default'},
                    'reason': 'SuccessfulRescale',
                    'message': 'Scaled to 3',
                    'lastTimestamp': '2024-01-15T10:00:00Z'
                }
            ]
        }

        result = hpa_detector.analyze_hpa_events(events, 'my-hpa', 'default')

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['message'], 'Scaled to 5')


class TestParseEventTime(unittest.TestCase):
    """Test parse_event_time function."""

    def test_parse_z_suffix(self):
        """Test parsing timestamp with Z suffix."""
        event = {'lastTimestamp': '2024-01-15T10:30:00Z'}
        result = hpa_detector.parse_event_time(event)

        self.assertIsNotNone(result)
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 30)

    def test_parse_with_microseconds(self):
        """Test parsing timestamp with microseconds."""
        event = {'eventTime': '2024-01-15T10:30:00.123456Z'}
        result = hpa_detector.parse_event_time(event)

        self.assertIsNotNone(result)

    def test_parse_no_timestamp(self):
        """Test parsing event with no timestamp."""
        event = {}
        result = hpa_detector.parse_event_time(event)

        self.assertIsNone(result)

    def test_fallback_to_first_timestamp(self):
        """Test fallback to firstTimestamp."""
        event = {'firstTimestamp': '2024-01-15T09:00:00Z'}
        result = hpa_detector.parse_event_time(event)

        self.assertIsNotNone(result)
        self.assertEqual(result.hour, 9)


class TestGetHpas(unittest.TestCase):
    """Test get_hpas function with mocking."""

    @patch('k8s_hpa_thrashing_detector.run_kubectl')
    def test_get_hpas_all_namespaces(self, mock_run):
        """Test getting HPAs from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'hpa1', 'namespace': 'default'}},
                {'metadata': {'name': 'hpa2', 'namespace': 'production'}}
            ]
        })

        hpas = hpa_detector.get_hpas()

        self.assertEqual(len(hpas['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_hpa_thrashing_detector.run_kubectl')
    def test_get_hpas_specific_namespace(self, mock_run):
        """Test getting HPAs from specific namespace."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'hpa1', 'namespace': 'production'}}
            ]
        })

        hpas = hpa_detector.get_hpas('production')

        self.assertEqual(len(hpas['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)


class TestPrintResults(unittest.TestCase):
    """Test print_results function."""

    def test_print_results_json(self):
        """Test print_results with JSON format."""
        results = [{
            'name': 'test-hpa',
            'namespace': 'default',
            'min_replicas': 1,
            'max_replicas': 10,
            'current_replicas': 5,
            'desired_replicas': 5,
            'issues': [],
            'is_thrashing': False,
            'scaling_events_count': 2,
            'recent_scaling_events': []
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = hpa_detector.print_results(results, 'json', False, False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'test-hpa')

    def test_print_results_with_thrashing(self):
        """Test print_results with thrashing HPA."""
        results = [{
            'name': 'thrashing-hpa',
            'namespace': 'default',
            'min_replicas': 1,
            'max_replicas': 10,
            'current_replicas': 5,
            'desired_replicas': 7,
            'issues': [{'type': 'thrashing', 'message': 'Thrashing detected: 6 events'}],
            'is_thrashing': True,
            'scaling_events_count': 6,
            'recent_scaling_events': []
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = hpa_detector.print_results(results, 'plain', False, False)

        output = f.getvalue()
        self.assertTrue(has_issues)
        self.assertIn('THRASHING', output)

    def test_print_results_warn_only(self):
        """Test print_results with warn_only flag."""
        results = [
            {
                'name': 'healthy-hpa',
                'namespace': 'default',
                'min_replicas': 1,
                'max_replicas': 10,
                'current_replicas': 5,
                'desired_replicas': 5,
                'issues': [],
                'is_thrashing': False,
                'scaling_events_count': 1,
                'recent_scaling_events': []
            },
            {
                'name': 'problem-hpa',
                'namespace': 'default',
                'min_replicas': 1,
                'max_replicas': 10,
                'current_replicas': 10,
                'desired_replicas': 10,
                'issues': [{'type': 'at_max', 'message': 'At max replicas'}],
                'is_thrashing': False,
                'scaling_events_count': 0,
                'recent_scaling_events': []
            }
        ]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = hpa_detector.print_results(results, 'json', True, False)

        output = f.getvalue()
        data = json.loads(output)

        # Only problem HPA should be in output
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'problem-hpa')


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
