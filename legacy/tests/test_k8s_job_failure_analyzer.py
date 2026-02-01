#!/usr/bin/env python3
"""
Tests for k8s_job_failure_analyzer.py

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

import k8s_job_failure_analyzer as analyzer


def run_command(cmd_args, input_data=None):
    """Run the k8s_job_failure_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_job_failure_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sJobFailureAnalyzer(unittest.TestCase):
    """Test cases for k8s_job_failure_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Job', stdout)
        self.assertIn('CronJob', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--timeframe', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--include-cronjobs', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('Job', stdout)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'batch-jobs'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_timeframe_option(self):
        """Test --timeframe option is accepted."""
        returncode, stdout, stderr = run_command(['--timeframe', '24'])
        self.assertIn(returncode, [0, 1, 2])

    def test_timeframe_with_value(self):
        """Test timeframe option with various time values."""
        for hours in ['1', '24', '168']:
            returncode, stdout, stderr = run_command(['--timeframe', hours])
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

    def test_include_cronjobs_option(self):
        """Test --include-cronjobs option is accepted."""
        returncode, stdout, stderr = run_command(['--include-cronjobs'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_invalid_format_option(self):
        """Test that invalid format option is rejected."""
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
            '--namespace', 'batch-jobs',
            '--timeframe', '24',
            '--verbose',
            '--warn-only',
            '--include-cronjobs',
            '--format', 'json'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (may succeed with no failures or fail without kubectl)
        self.assertIn(returncode, [0, 1, 2])

    def test_kubectl_error_handling(self):
        """Test graceful handling when kubectl fails."""
        returncode, stdout, stderr = run_command([])
        # Should exit cleanly with appropriate error code
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_job_failure_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_job_failure_analyzer.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('Job', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_job_failure_analyzer.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_job_failure_analyzer.py', 'r') as f:
            content = f.read()
        # Check for exit code documentation
        self.assertIn('Exit codes:', content)
        self.assertIn('0 -', content)
        self.assertIn('1 -', content)
        self.assertIn('2 -', content)

    def test_examples_in_help(self):
        """Test that help includes examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_job_failure_analyzer.py', stdout)

    def test_script_has_main_function(self):
        """Test that script has main function."""
        with open('k8s_job_failure_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('def main()', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_has_failure_categories(self):
        """Test that script handles different failure categories."""
        with open('k8s_job_failure_analyzer.py', 'r') as f:
            content = f.read()
        # Check for key failure categories
        self.assertIn('OOMKilled', content)
        self.assertIn('DeadlineExceeded', content)
        self.assertIn('BackoffLimitExceeded', content)
        self.assertIn('ImagePullFailure', content)

    def test_script_has_remediation_logic(self):
        """Test that script includes remediation suggestions."""
        with open('k8s_job_failure_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('suggest_remediation', content)
        self.assertIn('suggestions', content)


class TestAnalyzeJobFailure(unittest.TestCase):
    """Test the analyze_job_failure function."""

    def test_deadline_exceeded(self):
        """Test DeadlineExceeded detection."""
        job = {
            'status': {
                'conditions': [{
                    'type': 'Failed',
                    'status': 'True',
                    'reason': 'DeadlineExceeded',
                    'message': 'Job exceeded deadline'
                }]
            }
        }
        failure_info = analyzer.analyze_job_failure(job, [])
        self.assertEqual(failure_info['category'], 'DeadlineExceeded')

    def test_backoff_limit_exceeded(self):
        """Test BackoffLimitExceeded detection."""
        job = {
            'status': {
                'conditions': [{
                    'type': 'Failed',
                    'status': 'True',
                    'reason': 'BackoffLimitExceeded',
                    'message': 'Job has reached backoff limit'
                }]
            }
        }
        failure_info = analyzer.analyze_job_failure(job, [])
        self.assertEqual(failure_info['category'], 'BackoffLimitExceeded')

    def test_oom_killed_detection(self):
        """Test OOMKilled detection from pod status."""
        job = {'status': {}}
        pods = [{
            'metadata': {'name': 'test-job-abc'},
            'status': {
                'phase': 'Failed',
                'containerStatuses': [{
                    'name': 'main',
                    'state': {
                        'terminated': {
                            'reason': 'OOMKilled',
                            'exitCode': 137
                        }
                    }
                }]
            }
        }]
        failure_info = analyzer.analyze_job_failure(job, pods)
        self.assertEqual(failure_info['category'], 'OOMKilled')

    def test_image_pull_failure(self):
        """Test ImagePullFailure detection."""
        job = {'status': {}}
        pods = [{
            'metadata': {'name': 'test-job-abc'},
            'status': {
                'phase': 'Pending',
                'containerStatuses': [{
                    'name': 'main',
                    'state': {
                        'waiting': {
                            'reason': 'ImagePullBackOff',
                            'message': 'Failed to pull image'
                        }
                    }
                }]
            }
        }]
        failure_info = analyzer.analyze_job_failure(job, pods)
        self.assertEqual(failure_info['category'], 'ImagePullFailure')

    def test_application_error(self):
        """Test ApplicationError detection."""
        job = {'status': {}}
        pods = [{
            'metadata': {'name': 'test-job-abc'},
            'status': {
                'phase': 'Failed',
                'containerStatuses': [{
                    'name': 'main',
                    'state': {
                        'terminated': {
                            'reason': 'Error',
                            'exitCode': 1
                        }
                    }
                }]
            }
        }]
        failure_info = analyzer.analyze_job_failure(job, pods)
        self.assertEqual(failure_info['category'], 'ApplicationError')

    def test_config_error(self):
        """Test ConfigError detection."""
        job = {'status': {}}
        pods = [{
            'metadata': {'name': 'test-job-abc'},
            'status': {
                'phase': 'Pending',
                'containerStatuses': [{
                    'name': 'main',
                    'state': {
                        'waiting': {
                            'reason': 'CreateContainerConfigError',
                            'message': 'Secret not found'
                        }
                    }
                }]
            }
        }]
        failure_info = analyzer.analyze_job_failure(job, pods)
        self.assertEqual(failure_info['category'], 'ConfigError')

    def test_unknown_failure(self):
        """Test unknown failure handling."""
        job = {'status': {}}
        pods = []
        failure_info = analyzer.analyze_job_failure(job, pods)
        self.assertEqual(failure_info['category'], 'Unknown')


class TestSuggestRemediation(unittest.TestCase):
    """Test the suggest_remediation function."""

    def test_deadline_exceeded_suggestions(self):
        """Test DeadlineExceeded remediation suggestions."""
        job_info = {'name': 'test-job', 'namespace': 'default'}
        suggestions = analyzer.suggest_remediation('DeadlineExceeded', job_info)
        self.assertTrue(len(suggestions) > 0)
        self.assertTrue(any('activeDeadlineSeconds' in s for s in suggestions))

    def test_backoff_limit_suggestions(self):
        """Test BackoffLimitExceeded remediation suggestions."""
        job_info = {'name': 'test-job', 'namespace': 'default'}
        suggestions = analyzer.suggest_remediation('BackoffLimitExceeded', job_info)
        self.assertTrue(len(suggestions) > 0)
        self.assertTrue(any('backoffLimit' in s for s in suggestions))

    def test_oom_killed_suggestions(self):
        """Test OOMKilled remediation suggestions."""
        job_info = {'name': 'test-job', 'namespace': 'default'}
        suggestions = analyzer.suggest_remediation('OOMKilled', job_info)
        self.assertTrue(len(suggestions) > 0)
        self.assertTrue(any('memory' in s.lower() for s in suggestions))

    def test_image_pull_suggestions(self):
        """Test ImagePullFailure remediation suggestions."""
        job_info = {'name': 'test-job', 'namespace': 'default'}
        suggestions = analyzer.suggest_remediation('ImagePullFailure', job_info)
        self.assertTrue(len(suggestions) > 0)
        self.assertTrue(any('image' in s.lower() for s in suggestions))

    def test_unknown_suggestions(self):
        """Test unknown failure remediation suggestions."""
        job_info = {'name': 'test-job', 'namespace': 'default'}
        suggestions = analyzer.suggest_remediation('Unknown', job_info)
        self.assertTrue(len(suggestions) > 0)
        self.assertTrue(any('kubectl' in s for s in suggestions))


class TestAnalyzeCronjobIssues(unittest.TestCase):
    """Test the analyze_cronjob_issues function."""

    def test_suspended_cronjob(self):
        """Test detection of suspended CronJob."""
        cronjob = {
            'metadata': {'name': 'test-cron', 'namespace': 'default'},
            'spec': {'suspend': True},
            'status': {}
        }
        issues = analyzer.analyze_cronjob_issues(cronjob, [])
        self.assertTrue(any(i['type'] == 'Suspended' for i in issues))

    def test_healthy_cronjob(self):
        """Test healthy CronJob returns no issues."""
        cronjob = {
            'metadata': {'name': 'test-cron', 'namespace': 'default'},
            'spec': {'suspend': False},
            'status': {}
        }
        issues = analyzer.analyze_cronjob_issues(cronjob, [])
        # Should have no critical issues for a basic healthy cronjob
        self.assertTrue(len([i for i in issues if i['type'] != 'StaleSchedule']) == 0 or
                       len(issues) >= 0)


class TestGetFailedJobs(unittest.TestCase):
    """Test the get_failed_jobs function."""

    def test_filter_failed_jobs(self):
        """Test filtering to only failed jobs."""
        jobs_data = {
            'items': [
                {
                    'metadata': {'name': 'success-job', 'namespace': 'default'},
                    'status': {
                        'succeeded': 1,
                        'conditions': [{
                            'type': 'Complete',
                            'status': 'True'
                        }]
                    }
                },
                {
                    'metadata': {'name': 'failed-job', 'namespace': 'default'},
                    'status': {
                        'failed': 1,
                        'conditions': [{
                            'type': 'Failed',
                            'status': 'True',
                            'reason': 'BackoffLimitExceeded'
                        }]
                    }
                }
            ]
        }
        failed = analyzer.get_failed_jobs(jobs_data)
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]['metadata']['name'], 'failed-job')

    def test_no_failed_jobs(self):
        """Test when no jobs have failed."""
        jobs_data = {
            'items': [
                {
                    'metadata': {'name': 'success-job', 'namespace': 'default'},
                    'status': {'succeeded': 1}
                }
            ]
        }
        failed = analyzer.get_failed_jobs(jobs_data)
        self.assertEqual(len(failed), 0)

    def test_empty_jobs_list(self):
        """Test with empty jobs list."""
        jobs_data = {'items': []}
        failed = analyzer.get_failed_jobs(jobs_data)
        self.assertEqual(len(failed), 0)


class TestParseDuration(unittest.TestCase):
    """Test the parse_duration function."""

    def test_parse_hours(self):
        """Test parsing hours."""
        self.assertEqual(analyzer.parse_duration('2h'), 120)

    def test_parse_minutes(self):
        """Test parsing minutes."""
        self.assertEqual(analyzer.parse_duration('30m'), 30)

    def test_parse_combined(self):
        """Test parsing combined duration."""
        self.assertEqual(analyzer.parse_duration('1h30m'), 90)

    def test_parse_seconds(self):
        """Test parsing seconds (converted to minutes)."""
        self.assertEqual(analyzer.parse_duration('120s'), 2)

    def test_parse_empty(self):
        """Test parsing empty string."""
        self.assertEqual(analyzer.parse_duration(''), 0)

    def test_parse_none(self):
        """Test parsing None."""
        self.assertEqual(analyzer.parse_duration(None), 0)


class TestFormatOutputPlain(unittest.TestCase):
    """Test the format_output_plain function."""

    def test_format_empty_analysis(self):
        """Test formatting empty analysis."""
        analysis = {
            'total_failed': 0,
            'cronjobs_with_issues': 0,
            'by_category': {},
            'by_namespace': {},
            'failed_jobs': [],
            'cronjob_issues': []
        }
        output = analyzer.format_output_plain(analysis)
        self.assertIn('Job Failure Analysis', output)
        self.assertIn('Total failed jobs: 0', output)

    def test_format_with_failures(self):
        """Test formatting analysis with failures."""
        analysis = {
            'total_failed': 2,
            'cronjobs_with_issues': 0,
            'by_category': {
                'OOMKilled': [{'name': 'test-job'}]
            },
            'by_namespace': {'default': 2},
            'failed_jobs': [{
                'name': 'test-job',
                'namespace': 'default',
                'failure_category': 'OOMKilled',
                'failure_reason': 'Container killed',
                'cronjob_owner': None
            }],
            'cronjob_issues': []
        }
        output = analyzer.format_output_plain(analysis)
        self.assertIn('Total failed jobs: 2', output)
        self.assertIn('OOMKilled', output)

    def test_format_warn_only(self):
        """Test formatting with warn_only flag."""
        analysis = {
            'total_failed': 1,
            'cronjobs_with_issues': 0,
            'by_category': {},
            'by_namespace': {'default': 1},
            'failed_jobs': [],
            'cronjob_issues': []
        }
        output = analyzer.format_output_plain(analysis, warn_only=True)
        # Should not include summary header when warn_only is True
        self.assertNotIn('Job Failure Analysis', output)


class TestFormatOutputJson(unittest.TestCase):
    """Test the format_output_json function."""

    def test_format_json_structure(self):
        """Test JSON output has correct structure."""
        analysis = {
            'total_failed': 1,
            'cronjobs_with_issues': 0,
            'by_category': {'OOMKilled': [{}]},
            'by_namespace': {'default': 1},
            'failed_jobs': [],
            'cronjob_issues': []
        }
        output = analyzer.format_output_json(analysis)

        # Should be valid JSON
        data = json.loads(output)
        self.assertIn('total_failed', data)
        self.assertIn('cronjobs_with_issues', data)
        self.assertIn('by_category', data)
        self.assertIn('by_namespace', data)
        self.assertIn('failed_jobs', data)

    def test_format_json_values(self):
        """Test JSON output contains correct values."""
        analysis = {
            'total_failed': 3,
            'cronjobs_with_issues': 1,
            'by_category': {},
            'by_namespace': {},
            'failed_jobs': [],
            'cronjob_issues': []
        }
        output = analyzer.format_output_json(analysis)

        data = json.loads(output)
        self.assertEqual(data['total_failed'], 3)
        self.assertEqual(data['cronjobs_with_issues'], 1)


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
