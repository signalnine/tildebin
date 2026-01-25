#!/usr/bin/env python3
"""
Tests for k8s_job_monitor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and core functions.
"""

import subprocess
import sys
import unittest
from unittest.mock import patch
import json
import os
from datetime import datetime, timezone, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import k8s_job_monitor as job_monitor


def run_command(cmd_args, input_data=None):
    """Run the k8s_job_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_job_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sJobMonitor(unittest.TestCase):
    """Test cases for k8s_job_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Job', stdout)
        self.assertIn('CronJob', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('Job', stdout)

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

    def test_failed_only_option(self):
        """Test --failed-only option is accepted."""
        returncode, stdout, stderr = run_command(['--failed-only'])
        self.assertIn(returncode, [1, 2])

    def test_max_duration_option(self):
        """Test --max-duration option is accepted."""
        returncode, stdout, stderr = run_command(['--max-duration', '12'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command([
            '--format', 'plain',
            '--warn-only',
            '--namespace', 'kube-system',
            '--max-duration', '48'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
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
        with open('k8s_job_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_job_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('Job', content[:500])
        self.assertIn('CronJob', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_job_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestCheckJobStatus(unittest.TestCase):
    """Test check_job_status function."""

    def test_healthy_completed_job(self):
        """Test status checking for healthy completed job."""
        job = {
            'metadata': {'name': 'test-job', 'namespace': 'default'},
            'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 6},
            'status': {
                'succeeded': 1,
                'failed': 0,
                'active': 0,
                'startTime': '2024-01-15T10:00:00Z',
                'completionTime': '2024-01-15T10:05:00Z',
                'conditions': []
            }
        }

        is_healthy, issues, info = job_monitor.check_job_status(job)

        self.assertTrue(is_healthy)
        self.assertEqual(len(issues), 0)
        self.assertEqual(info['succeeded'], 1)
        self.assertEqual(info['completions'], 1)

    def test_active_job(self):
        """Test status checking for active (running) job."""
        job = {
            'metadata': {'name': 'test-job', 'namespace': 'default'},
            'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 6},
            'status': {
                'succeeded': 0,
                'failed': 0,
                'active': 1,
                'startTime': '2024-01-15T10:00:00Z',
                'conditions': []
            }
        }

        is_healthy, issues, info = job_monitor.check_job_status(job)

        # Active job is healthy as long as it hasn't exceeded duration
        self.assertEqual(info['active'], 1)

    def test_failed_job(self):
        """Test status checking for failed job."""
        job = {
            'metadata': {'name': 'test-job', 'namespace': 'default'},
            'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 6},
            'status': {
                'succeeded': 0,
                'failed': 6,
                'active': 0,
                'startTime': '2024-01-15T10:00:00Z',
                'conditions': [
                    {
                        'type': 'Failed',
                        'status': 'True',
                        'reason': 'BackoffLimitExceeded',
                        'message': 'Job has reached the backoff limit'
                    }
                ]
            }
        }

        is_healthy, issues, info = job_monitor.check_job_status(job)

        self.assertFalse(is_healthy)
        self.assertTrue(any('failed' in issue.lower() for issue in issues))

    def test_job_with_some_failures(self):
        """Test job that has some failures but not at backoff limit."""
        job = {
            'metadata': {'name': 'test-job', 'namespace': 'default'},
            'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 6},
            'status': {
                'succeeded': 0,
                'failed': 2,
                'active': 1,
                'startTime': '2024-01-15T10:00:00Z',
                'conditions': []
            }
        }

        is_healthy, issues, info = job_monitor.check_job_status(job)

        # Has failures but still active and under limit
        self.assertEqual(info['failed'], 2)
        self.assertTrue(any('failure' in issue.lower() for issue in issues))

    def test_job_reached_backoff_limit(self):
        """Test job that has reached backoff limit."""
        job = {
            'metadata': {'name': 'test-job', 'namespace': 'default'},
            'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 3},
            'status': {
                'succeeded': 0,
                'failed': 3,
                'active': 0,
                'startTime': '2024-01-15T10:00:00Z',
                'conditions': []
            }
        }

        is_healthy, issues, info = job_monitor.check_job_status(job)

        self.assertFalse(is_healthy)
        self.assertTrue(any('backoff limit' in issue.lower() for issue in issues))

    def test_job_partial_completion(self):
        """Test job with partial completion."""
        job = {
            'metadata': {'name': 'test-job', 'namespace': 'default'},
            'spec': {'completions': 5, 'parallelism': 2, 'backoffLimit': 6},
            'status': {
                'succeeded': 3,
                'failed': 0,
                'active': 0,
                'startTime': '2024-01-15T10:00:00Z',
                'completionTime': '2024-01-15T10:10:00Z',
                'conditions': []
            }
        }

        is_healthy, issues, info = job_monitor.check_job_status(job)

        self.assertFalse(is_healthy)
        self.assertTrue(any('3/5' in issue for issue in issues))


class TestCheckCronJobStatus(unittest.TestCase):
    """Test check_cronjob_status function."""

    def test_healthy_cronjob(self):
        """Test status checking for healthy cronjob."""
        # Use recent timestamps to avoid "no successful run" warning
        recent_time = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        cronjob = {
            'metadata': {'name': 'test-cronjob', 'namespace': 'default'},
            'spec': {
                'schedule': '*/5 * * * *',
                'suspend': False,
                'concurrencyPolicy': 'Allow'
            },
            'status': {
                'lastScheduleTime': recent_time,
                'lastSuccessfulTime': recent_time,
                'active': []
            }
        }

        is_healthy, issues, info = job_monitor.check_cronjob_status(cronjob)

        self.assertTrue(is_healthy)
        self.assertEqual(info['schedule'], '*/5 * * * *')
        self.assertFalse(info['suspend'])

    def test_suspended_cronjob(self):
        """Test status checking for suspended cronjob."""
        cronjob = {
            'metadata': {'name': 'test-cronjob', 'namespace': 'default'},
            'spec': {
                'schedule': '*/5 * * * *',
                'suspend': True,
                'concurrencyPolicy': 'Allow'
            },
            'status': {
                'lastScheduleTime': '2024-01-15T10:05:00Z',
                'active': []
            }
        }

        is_healthy, issues, info = job_monitor.check_cronjob_status(cronjob)

        self.assertTrue(info['suspend'])
        self.assertTrue(any('suspended' in issue.lower() for issue in issues))

    def test_cronjob_never_scheduled(self):
        """Test cronjob that has never been scheduled."""
        cronjob = {
            'metadata': {'name': 'test-cronjob', 'namespace': 'default'},
            'spec': {
                'schedule': '*/5 * * * *',
                'suspend': False,
                'concurrencyPolicy': 'Allow'
            },
            'status': {
                'active': []
            }
        }

        is_healthy, issues, info = job_monitor.check_cronjob_status(cronjob)

        self.assertTrue(any('never been scheduled' in issue.lower() for issue in issues))

    def test_cronjob_multiple_active_forbid(self):
        """Test cronjob with multiple active jobs and Forbid policy."""
        cronjob = {
            'metadata': {'name': 'test-cronjob', 'namespace': 'default'},
            'spec': {
                'schedule': '*/5 * * * *',
                'suspend': False,
                'concurrencyPolicy': 'Forbid'
            },
            'status': {
                'lastScheduleTime': '2024-01-15T10:05:00Z',
                'active': [
                    {'name': 'job-1'},
                    {'name': 'job-2'}
                ]
            }
        }

        is_healthy, issues, info = job_monitor.check_cronjob_status(cronjob)

        self.assertFalse(is_healthy)
        self.assertTrue(any('Multiple active jobs' in issue for issue in issues))


class TestFormatDuration(unittest.TestCase):
    """Test format_duration function."""

    def test_format_seconds(self):
        """Test formatting seconds."""
        self.assertEqual(job_monitor.format_duration(30), '30s')
        self.assertEqual(job_monitor.format_duration(59), '59s')

    def test_format_minutes(self):
        """Test formatting minutes."""
        self.assertEqual(job_monitor.format_duration(60), '1m0s')
        self.assertEqual(job_monitor.format_duration(90), '1m30s')
        self.assertEqual(job_monitor.format_duration(3599), '59m59s')

    def test_format_hours(self):
        """Test formatting hours."""
        self.assertEqual(job_monitor.format_duration(3600), '1h0m')
        self.assertEqual(job_monitor.format_duration(3660), '1h1m')
        self.assertEqual(job_monitor.format_duration(7200), '2h0m')

    def test_format_none(self):
        """Test formatting None."""
        self.assertEqual(job_monitor.format_duration(None), 'unknown')


class TestParseDuration(unittest.TestCase):
    """Test parse_duration function."""

    def test_parse_with_completion(self):
        """Test parsing duration with start and completion time."""
        start = '2024-01-15T10:00:00Z'
        end = '2024-01-15T10:05:00Z'

        duration = job_monitor.parse_duration(start, end)

        self.assertEqual(duration, 300)  # 5 minutes in seconds

    def test_parse_no_start_time(self):
        """Test parsing with no start time."""
        duration = job_monitor.parse_duration(None)
        self.assertIsNone(duration)

    def test_parse_invalid_format(self):
        """Test parsing with invalid time format."""
        duration = job_monitor.parse_duration('invalid-time')
        self.assertIsNone(duration)


class TestGetJobs(unittest.TestCase):
    """Test get_jobs function with mocking."""

    @patch('k8s_job_monitor.run_kubectl')
    def test_get_jobs_all_namespaces(self, mock_run):
        """Test getting jobs from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'job1', 'namespace': 'default'}},
                {'metadata': {'name': 'job2', 'namespace': 'kube-system'}}
            ]
        })

        jobs = job_monitor.get_jobs()

        self.assertEqual(len(jobs['items']), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_job_monitor.run_kubectl')
    def test_get_jobs_specific_namespace(self, mock_run):
        """Test getting jobs from specific namespace."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'job1', 'namespace': 'production'}}
            ]
        })

        jobs = job_monitor.get_jobs('production')

        self.assertEqual(len(jobs['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)


class TestGetCronJobs(unittest.TestCase):
    """Test get_cronjobs function with mocking."""

    @patch('k8s_job_monitor.run_kubectl')
    def test_get_cronjobs_all_namespaces(self, mock_run):
        """Test getting cronjobs from all namespaces."""
        mock_run.return_value = json.dumps({
            'items': [
                {'metadata': {'name': 'cronjob1', 'namespace': 'default'}}
            ]
        })

        cronjobs = job_monitor.get_cronjobs()

        self.assertEqual(len(cronjobs['items']), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)


class TestPrintStatus(unittest.TestCase):
    """Test print_status function."""

    def test_print_status_json_format(self):
        """Test print_status with JSON format."""
        jobs = {
            'items': [{
                'metadata': {'name': 'test-job', 'namespace': 'default'},
                'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 6},
                'status': {
                    'succeeded': 1,
                    'failed': 0,
                    'active': 0,
                    'startTime': '2024-01-15T10:00:00Z',
                    'completionTime': '2024-01-15T10:05:00Z',
                    'conditions': []
                }
            }]
        }
        cronjobs = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = job_monitor.print_status(jobs, cronjobs, 'json', False, False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIn('jobs', data)
        self.assertIn('cronjobs', data)

    def test_print_status_plain_format(self):
        """Test print_status with plain format."""
        jobs = {
            'items': [{
                'metadata': {'name': 'test-job', 'namespace': 'default'},
                'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 6},
                'status': {
                    'succeeded': 1,
                    'failed': 0,
                    'active': 0,
                    'startTime': '2024-01-15T10:00:00Z',
                    'completionTime': '2024-01-15T10:05:00Z',
                    'conditions': []
                }
            }]
        }
        cronjobs = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = job_monitor.print_status(jobs, cronjobs, 'plain', False, False)

        output = f.getvalue()
        self.assertIn('test-job', output)
        self.assertIn('Jobs', output)
        self.assertIn('CronJobs', output)

    def test_print_status_warn_only(self):
        """Test print_status with warn_only flag."""
        jobs = {
            'items': [
                {
                    'metadata': {'name': 'healthy-job', 'namespace': 'default'},
                    'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 6},
                    'status': {
                        'succeeded': 1,
                        'failed': 0,
                        'active': 0,
                        'startTime': '2024-01-15T10:00:00Z',
                        'completionTime': '2024-01-15T10:05:00Z',
                        'conditions': []
                    }
                },
                {
                    'metadata': {'name': 'failed-job', 'namespace': 'default'},
                    'spec': {'completions': 1, 'parallelism': 1, 'backoffLimit': 3},
                    'status': {
                        'succeeded': 0,
                        'failed': 3,
                        'active': 0,
                        'startTime': '2024-01-15T10:00:00Z',
                        'conditions': [
                            {'type': 'Failed', 'status': 'True', 'reason': 'BackoffLimitExceeded', 'message': 'Test'}
                        ]
                    }
                }
            ]
        }
        cronjobs = {'items': []}

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = job_monitor.print_status(jobs, cronjobs, 'json', True, False)

        output = f.getvalue()
        data = json.loads(output)

        # Only failed job should be in output
        self.assertEqual(len(data['jobs']), 1)
        self.assertEqual(data['jobs'][0]['name'], 'failed-job')
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
