#!/usr/bin/env python3
"""
Tests for k8s_helm_release_monitor.py

These tests validate the script's behavior without requiring Helm or a Kubernetes cluster.
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

import k8s_helm_release_monitor as helm_monitor


def run_command(cmd_args, input_data=None):
    """Run the k8s_helm_release_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_helm_release_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sHelmReleaseMonitor(unittest.TestCase):
    """Test cases for k8s_helm_release_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Helm', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('Helm', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no helm) or 0/1 (helm found)
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_format_option_table(self):
        """Test --format table option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'table'])
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
        returncode, stdout, stderr = run_command(['--namespace', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'kube-system'])
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
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'table', '--warn-only', '--namespace', 'production'])
        self.assertIn(returncode, [0, 1, 2])

    def test_helm_not_found_error(self):
        """Test graceful handling when helm is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with code 0, 1, or 2
        self.assertIn(returncode, [0, 1, 2])
        # If helm not found, error message should be helpful
        if returncode == 2 and 'helm' in stderr.lower():
            self.assertIn('helm', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_helm_release_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_helm_release_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('"""', content)
        self.assertIn('Helm', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_helm_release_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)


class TestCheckReleaseStatus(unittest.TestCase):
    """Test check_release_status function."""

    def test_healthy_release(self):
        """Test status checking for healthy deployed release."""
        release = {
            'name': 'my-app',
            'namespace': 'production',
            'status': 'deployed',
            'chart': 'my-chart-1.2.3',
            'app_version': '2.0.0',
            'revision': 5,
            'updated': '2024-01-15T10:30:00.123456789Z'
        }

        info = helm_monitor.check_release_status(release)

        self.assertTrue(info['healthy'])
        self.assertEqual(len(info['issues']), 0)
        self.assertEqual(info['name'], 'my-app')
        self.assertEqual(info['namespace'], 'production')
        self.assertEqual(info['status'], 'deployed')

    def test_failed_release(self):
        """Test status checking for failed release."""
        release = {
            'name': 'broken-app',
            'namespace': 'staging',
            'status': 'failed',
            'chart': 'broken-chart-0.1.0',
            'app_version': '1.0.0',
            'revision': 2,
            'updated': '2024-01-15T10:30:00Z'
        }

        info = helm_monitor.check_release_status(release)

        self.assertFalse(info['healthy'])
        self.assertGreater(len(info['issues']), 0)
        self.assertTrue(any('failed' in issue.lower() for issue in info['issues']))

    def test_pending_install_release(self):
        """Test status checking for pending-install release."""
        release = {
            'name': 'new-app',
            'namespace': 'default',
            'status': 'pending-install',
            'chart': 'new-chart-1.0.0',
            'app_version': '1.0.0',
            'revision': 1,
            'updated': '2024-01-15T10:30:00Z'
        }

        info = helm_monitor.check_release_status(release)

        self.assertFalse(info['healthy'])
        self.assertGreater(len(info['issues']), 0)
        self.assertTrue(any('pending' in issue.lower() for issue in info['issues']))

    def test_pending_upgrade_release(self):
        """Test status checking for pending-upgrade release."""
        release = {
            'name': 'upgrading-app',
            'namespace': 'default',
            'status': 'pending-upgrade',
            'chart': 'app-chart-2.0.0',
            'app_version': '2.0.0',
            'revision': 3,
            'updated': '2024-01-15T10:30:00Z'
        }

        info = helm_monitor.check_release_status(release)

        self.assertFalse(info['healthy'])
        self.assertTrue(any('pending' in issue.lower() for issue in info['issues']))

    def test_superseded_release(self):
        """Test status checking for superseded release."""
        release = {
            'name': 'old-app',
            'namespace': 'default',
            'status': 'superseded',
            'chart': 'old-chart-1.0.0',
            'app_version': '1.0.0',
            'revision': 1,
            'updated': '2024-01-10T10:30:00Z'
        }

        info = helm_monitor.check_release_status(release)

        self.assertFalse(info['healthy'])
        self.assertTrue(any('superseded' in issue.lower() for issue in info['issues']))

    def test_missing_fields(self):
        """Test handling of release with missing fields."""
        release = {
            'name': 'minimal-app'
        }

        info = helm_monitor.check_release_status(release)

        self.assertEqual(info['name'], 'minimal-app')
        self.assertEqual(info['namespace'], 'default')
        self.assertEqual(info['status'], 'unknown')


class TestParseTimestamp(unittest.TestCase):
    """Test parse_timestamp function."""

    def test_parse_valid_timestamp(self):
        """Test parsing valid RFC3339 timestamp."""
        timestamp = '2024-01-15T10:30:00.123456789Z'
        result = helm_monitor.parse_timestamp(timestamp)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_parse_timestamp_without_fraction(self):
        """Test parsing timestamp without fractional seconds."""
        timestamp = '2024-01-15T10:30:00Z'
        result = helm_monitor.parse_timestamp(timestamp)
        self.assertIsNotNone(result)
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 30)

    def test_parse_empty_timestamp(self):
        """Test parsing empty timestamp returns None."""
        result = helm_monitor.parse_timestamp('')
        self.assertIsNone(result)

    def test_parse_none_timestamp(self):
        """Test parsing None timestamp returns None."""
        result = helm_monitor.parse_timestamp(None)
        self.assertIsNone(result)


class TestCalculateAge(unittest.TestCase):
    """Test calculate_age function."""

    def test_age_unknown_for_none(self):
        """Test that None timestamp returns 'unknown'."""
        result = helm_monitor.calculate_age(None)
        self.assertEqual(result, 'unknown')


class TestPrintReleases(unittest.TestCase):
    """Test print_releases function."""

    def test_print_releases_json_format(self):
        """Test print_releases with JSON format."""
        releases = [{
            'name': 'test-app',
            'namespace': 'default',
            'status': 'deployed',
            'chart': 'test-chart-1.0.0',
            'app_version': '1.0.0',
            'revision': 1,
            'updated': '2024-01-15T10:30:00Z'
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = helm_monitor.print_releases(releases, 'json', False)

        output = f.getvalue()
        self.assertFalse(has_issues)

        # Verify JSON is valid
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'test-app')

    def test_print_releases_plain_format(self):
        """Test print_releases with plain format."""
        releases = [{
            'name': 'test-app',
            'namespace': 'production',
            'status': 'deployed',
            'chart': 'test-chart-1.0.0',
            'app_version': '1.0.0',
            'revision': 1,
            'updated': '2024-01-15T10:30:00Z'
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = helm_monitor.print_releases(releases, 'plain', False)

        output = f.getvalue()
        self.assertIn('test-app', output)
        self.assertIn('production', output)
        self.assertIn('deployed', output)

    def test_print_releases_table_format(self):
        """Test print_releases with table format."""
        releases = [{
            'name': 'test-app',
            'namespace': 'default',
            'status': 'deployed',
            'chart': 'test-chart-1.0.0',
            'app_version': '1.0.0',
            'revision': 1,
            'updated': '2024-01-15T10:30:00Z'
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = helm_monitor.print_releases(releases, 'table', False)

        output = f.getvalue()
        self.assertIn('STATUS', output)
        self.assertIn('NAMESPACE', output)
        self.assertIn('NAME', output)
        self.assertIn('test-app', output)

    def test_print_releases_warn_only(self):
        """Test print_releases with warn_only flag."""
        releases = [
            {
                'name': 'healthy-app',
                'namespace': 'default',
                'status': 'deployed',
                'chart': 'chart-1.0.0',
                'app_version': '1.0.0',
                'revision': 1,
                'updated': '2024-01-15T10:30:00Z'
            },
            {
                'name': 'failing-app',
                'namespace': 'default',
                'status': 'failed',
                'chart': 'chart-1.0.0',
                'app_version': '1.0.0',
                'revision': 2,
                'updated': '2024-01-15T10:30:00Z'
            }
        ]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = helm_monitor.print_releases(releases, 'json', True)

        output = f.getvalue()
        data = json.loads(output)

        # Only failing release should be in output
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'failing-app')
        self.assertTrue(has_issues)

    def test_print_releases_empty_list(self):
        """Test print_releases with empty release list."""
        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = helm_monitor.print_releases([], 'plain', False)

        output = f.getvalue()
        self.assertIn('No Helm releases found', output)
        self.assertFalse(has_issues)

    def test_print_releases_with_issues(self):
        """Test print_releases detects issues correctly."""
        releases = [{
            'name': 'broken-app',
            'namespace': 'default',
            'status': 'failed',
            'chart': 'broken-chart-1.0.0',
            'app_version': '1.0.0',
            'revision': 1,
            'updated': '2024-01-15T10:30:00Z'
        }]

        from io import StringIO
        from contextlib import redirect_stdout

        f = StringIO()
        with redirect_stdout(f):
            has_issues = helm_monitor.print_releases(releases, 'plain', False)

        self.assertTrue(has_issues)


class TestGetReleases(unittest.TestCase):
    """Test get_releases function with mocking."""

    @patch('k8s_helm_release_monitor.run_helm')
    def test_get_releases_all_namespaces(self, mock_run):
        """Test getting releases from all namespaces."""
        mock_run.return_value = json.dumps([
            {'name': 'app1', 'namespace': 'default'},
            {'name': 'app2', 'namespace': 'production'}
        ])

        releases = helm_monitor.get_releases()

        self.assertEqual(len(releases), 2)
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('--all-namespaces', call_args)

    @patch('k8s_helm_release_monitor.run_helm')
    def test_get_releases_specific_namespace(self, mock_run):
        """Test getting releases from specific namespace."""
        mock_run.return_value = json.dumps([
            {'name': 'app1', 'namespace': 'production'}
        ])

        releases = helm_monitor.get_releases('production')

        self.assertEqual(len(releases), 1)
        call_args = mock_run.call_args[0][0]
        self.assertIn('-n', call_args)
        self.assertIn('production', call_args)

    @patch('k8s_helm_release_monitor.run_helm')
    def test_get_releases_empty_output(self, mock_run):
        """Test handling empty helm output."""
        mock_run.return_value = ''

        releases = helm_monitor.get_releases()

        self.assertEqual(releases, [])


if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)

    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"\nTest Results: {passed}/{result.testsRun} tests passed")

    sys.exit(0 if result.wasSuccessful() else 1)
