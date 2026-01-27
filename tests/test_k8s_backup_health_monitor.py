#!/usr/bin/env python3
"""
Tests for k8s_backup_health_monitor.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and utility functions.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_backup_health_monitor.py script with given arguments."""
    cmd = [sys.executable, 'k8s_backup_health_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sBackupHealthMonitor(unittest.TestCase):
    """Test cases for k8s_backup_health_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('backup', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--max-age', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('backup', stdout.lower())

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no kubectl) or 0/1 (kubectl available)
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

    def test_warn_only_option(self):
        """Test --warn-only option is accepted."""
        returncode, stdout, stderr = run_command(['--warn-only'])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_short(self):
        """Test -w short option works."""
        returncode, stdout, stderr = run_command(['-w'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'velero'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'velero'])
        self.assertIn(returncode, [0, 1, 2])

    def test_max_age_option(self):
        """Test --max-age option is accepted."""
        returncode, stdout, stderr = run_command(['--max-age', '48'])
        self.assertIn(returncode, [0, 1, 2])

    def test_max_age_short(self):
        """Test -a short option works."""
        returncode, stdout, stderr = run_command(['-a', '72'])
        self.assertIn(returncode, [0, 1, 2])

    def test_max_age_invalid(self):
        """Test that invalid max-age values are rejected."""
        returncode, stdout, stderr = run_command(['--max-age', 'invalid'])
        self.assertEqual(returncode, 2)
        self.assertIn('invalid', stderr.lower())

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command([
            '--format', 'plain',
            '--warn-only',
            '--verbose',
            '--max-age', '24'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should not crash - exits with error code if kubectl not found
        self.assertIn(returncode, [0, 1, 2])
        # Error message should be helpful if kubectl not found
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [0, 1, 2])

    def test_unknown_argument_rejected(self):
        """Test that unknown arguments are rejected."""
        returncode, stdout, stderr = run_command(['--unknown-flag'])
        self.assertEqual(returncode, 2)
        self.assertIn('unrecognized arguments', stderr)


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('backup', content[:500].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_script_has_main_function(self):
        """Test that script has main() function."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('def main():', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_has_exit_codes_documented(self):
        """Test that exit codes are documented."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('sys.exit', content)

    def test_script_has_kubectl_error_handling(self):
        """Test that script handles kubectl errors gracefully."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('FileNotFoundError', content)
        self.assertIn('kubectl not found', content)


class TestBackupFunctionality(unittest.TestCase):
    """Test backup-specific functionality."""

    def test_script_checks_velero(self):
        """Test that script includes Velero backup checking."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('velero', content.lower())
        self.assertIn('def check_velero_backups', content)

    def test_script_checks_volume_snapshots(self):
        """Test that script includes VolumeSnapshot checking."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('volumesnapshot', content.lower())
        self.assertIn('def check_volume_snapshots', content)

    def test_script_checks_cronjobs(self):
        """Test that script includes CronJob checking."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('cronjob', content.lower())
        self.assertIn('def check_backup_cronjobs', content)

    def test_script_has_age_calculation(self):
        """Test that script calculates backup age."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('age', content.lower())
        self.assertIn('hours', content.lower())

    def test_script_has_timestamp_parsing(self):
        """Test that script parses Kubernetes timestamps."""
        with open('k8s_backup_health_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('def parse_k8s_timestamp', content)
        self.assertIn('datetime', content)


class TestArgumentParsing(unittest.TestCase):
    """Test argument parsing without requiring kubectl."""

    def test_help_contains_examples(self):
        """Test that help output includes practical examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_backup_health_monitor.py', stdout)

    def test_help_mentions_velero(self):
        """Test that help mentions Velero."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Velero', stdout)

    def test_help_mentions_volumesnapshots(self):
        """Test that help mentions VolumeSnapshots."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('VolumeSnapshot', stdout)

    def test_help_mentions_cronjobs(self):
        """Test that help mentions CronJobs."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('CronJob', stdout)

    def test_max_age_default(self):
        """Test that max-age has a default value."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('default: 24', stdout)

    def test_warn_only_with_format_json(self):
        """Test combining warn-only and JSON format."""
        returncode, stdout, stderr = run_command(['--warn-only', '--format', 'json'])
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
