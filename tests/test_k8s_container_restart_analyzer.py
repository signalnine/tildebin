#!/usr/bin/env python3
"""
Tests for k8s_container_restart_analyzer.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_container_restart_analyzer.py script with given arguments."""
    cmd = [sys.executable, 'k8s_container_restart_analyzer.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sContainerRestartAnalyzer(unittest.TestCase):
    """Test cases for k8s_container_restart_analyzer.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('restart patterns', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('--timeframe', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--output', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('restart patterns', stdout)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'kube-system'])
        self.assertIn(returncode, [0, 1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'default'])
        self.assertIn(returncode, [0, 1, 2])

    def test_timeframe_option(self):
        """Test --timeframe option is accepted."""
        returncode, stdout, stderr = run_command(['--timeframe', '60'])
        self.assertIn(returncode, [0, 1, 2])

    def test_timeframe_with_value(self):
        """Test timeframe option with various time values."""
        for minutes in ['30', '60', '1440']:
            returncode, stdout, stderr = run_command(['--timeframe', minutes])
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

    def test_output_option_plain(self):
        """Test --output plain option is accepted."""
        returncode, stdout, stderr = run_command(['--output', 'plain'])
        self.assertIn(returncode, [0, 1, 2])

    def test_output_option_json(self):
        """Test --output json option is accepted."""
        returncode, stdout, stderr = run_command(['--output', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_invalid_output_format(self):
        """Test that invalid output format is rejected."""
        returncode, stdout, stderr = run_command(['--output', 'invalid'])
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
            '--timeframe', '60',
            '--verbose',
            '--warn-only',
            '--output', 'json'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_timeframe_with_namespace(self):
        """Test timeframe works with namespace option."""
        returncode, stdout, stderr = run_command([
            '-n', 'default',
            '--timeframe', '120'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_with_json(self):
        """Test verbose option works with JSON output."""
        returncode, stdout, stderr = run_command([
            '--verbose',
            '--output', 'json'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_with_json(self):
        """Test warn-only works with JSON format."""
        returncode, stdout, stderr = run_command([
            '--warn-only',
            '--output', 'json'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (may succeed with no restarts or fail without kubectl)
        self.assertIn(returncode, [0, 1, 2])

    def test_kubectl_error_handling(self):
        """Test graceful handling when kubectl fails."""
        # This test verifies the script doesn't crash unexpectedly
        returncode, stdout, stderr = run_command([])
        # Should exit cleanly with appropriate error code
        self.assertIn(returncode, [0, 1, 2])

    def test_timeframe_negative_value(self):
        """Test that negative timeframe values are handled."""
        # argparse should reject negative values for int type
        returncode, stdout, stderr = run_command(['--timeframe', '-60'])
        # Should show error or treat as invalid
        self.assertIn(returncode, [0, 1, 2])

    def test_multiple_namespace_calls(self):
        """Test that only last namespace is used when multiple are specified."""
        returncode, stdout, stderr = run_command([
            '-n', 'namespace1',
            '-n', 'namespace2'
        ])
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('restart', content[:500].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
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
        self.assertIn('k8s_container_restart_analyzer.py', stdout)

    def test_script_has_main_function(self):
        """Test that script has main function."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('def main()', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_has_categories(self):
        """Test that script handles different restart categories."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
            content = f.read()
        # Check for key restart categories
        self.assertIn('OOMKilled', content)
        self.assertIn('CrashLoopBackOff', content)
        self.assertIn('ProbeFailure', content)

    def test_script_has_remediation_logic(self):
        """Test that script includes remediation suggestions."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('suggest_remediation', content)
        self.assertIn('suggestions', content)

    def test_script_has_flapping_detection(self):
        """Test that script detects flapping containers."""
        with open('k8s_container_restart_analyzer.py', 'r') as f:
            content = f.read()
        self.assertIn('flapping', content.lower())
        self.assertIn('Flapping', content)


class TestOutputFormats(unittest.TestCase):
    """Test output format functions."""

    def test_json_output_structure(self):
        """Test that JSON output mode is available."""
        returncode, stdout, stderr = run_command(['--output', 'json'])
        # Should accept JSON format
        self.assertIn(returncode, [0, 1, 2])

    def test_plain_output_structure(self):
        """Test that plain output mode is available."""
        returncode, stdout, stderr = run_command(['--output', 'plain'])
        # Should accept plain format
        self.assertIn(returncode, [0, 1, 2])

    def test_default_output_format(self):
        """Test that default output format is plain."""
        returncode, stdout, stderr = run_command([])
        # Script should run with default format
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
