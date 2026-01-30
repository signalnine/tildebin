#!/usr/bin/env python3
"""
Tests for k8s_pvc_stuck_detector.py

These tests validate the script's behavior without requiring a real Kubernetes cluster.
Tests cover argument parsing, help messages, error handling, and script structure.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the k8s_pvc_stuck_detector.py script with given arguments."""
    cmd = [sys.executable, 'k8s_pvc_stuck_detector.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestK8sPVCStuckDetector(unittest.TestCase):
    """Test cases for k8s_pvc_stuck_detector.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('stuck', stdout.lower())
        self.assertIn('pending', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--threshold', stdout)
        self.assertIn('--namespace', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('pvc', stdout.lower())

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Will fail without kubectl, but should parse args correctly
        self.assertIn(returncode, [1, 2])

    def test_format_option_json(self):
        """Test --format json option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_format_option_table(self):
        """Test --format table option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'table'])
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

    def test_threshold_option(self):
        """Test --threshold option is accepted."""
        returncode, stdout, stderr = run_command(['--threshold', '10'])
        self.assertIn(returncode, [1, 2])

    def test_threshold_option_short(self):
        """Test -t short option works."""
        returncode, stdout, stderr = run_command(['-t', '30'])
        self.assertIn(returncode, [1, 2])

    def test_threshold_zero(self):
        """Test threshold of 0 is accepted."""
        returncode, stdout, stderr = run_command(['-t', '0'])
        self.assertIn(returncode, [1, 2])

    def test_threshold_negative_rejected(self):
        """Test that negative threshold is rejected."""
        returncode, stdout, stderr = run_command(['-t', '-5'])
        # argparse may reject negative or script may reject it
        self.assertEqual(returncode, 2)

    def test_namespace_option(self):
        """Test --namespace option is accepted."""
        returncode, stdout, stderr = run_command(['--namespace', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_namespace_option_short(self):
        """Test -n short option works."""
        returncode, stdout, stderr = run_command(['-n', 'kube-system'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [1, 2])

    def test_verbose_option_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-t', '60', '-n', 'default'])
        self.assertIn(returncode, [1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command([
            '--format', 'table',
            '--threshold', '15',
            '--namespace', 'default',
            '--verbose'
        ])
        self.assertIn(returncode, [1, 2])

    def test_kubectl_not_found_error(self):
        """Test graceful handling when kubectl is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 1 or 2
        self.assertNotEqual(returncode, 0)
        # Error message should be helpful if kubectl not found
        if returncode == 2:
            self.assertIn('kubectl', stderr.lower())

    def test_no_arguments_uses_defaults(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without kubectl, but args are valid)
        self.assertIn(returncode, [1, 2])

    def test_unknown_argument_rejected(self):
        """Test that unknown arguments are rejected."""
        returncode, stdout, stderr = run_command(['--unknown-flag'])
        self.assertEqual(returncode, 2)
        self.assertIn('unrecognized arguments', stderr)


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('pending', content[:1000].lower())
        self.assertIn('stuck', content[:1000].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_script_has_main_function(self):
        """Test that script has main() function."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('def main():', content)
        self.assertIn("if __name__ == '__main__':", content)

    def test_script_has_exit_codes_documented(self):
        """Test that exit codes are documented."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content)
        self.assertIn('sys.exit', content)

    def test_script_has_kubectl_error_handling(self):
        """Test that script handles kubectl errors gracefully."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('FileNotFoundError', content)
        self.assertIn('kubectl not found', content)

    def test_script_has_diagnostic_functions(self):
        """Test that script has diagnostic logic."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('def diagnose_stuck_pvc', content)
        self.assertIn('StorageClass', content)
        self.assertIn('Pending', content)

    def test_script_has_format_functions(self):
        """Test that script has output formatting functions."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('def print_plain', content)
        self.assertIn('def print_json', content)
        self.assertIn('def print_table', content)

    def test_script_handles_storage_classes(self):
        """Test that script checks storage classes."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('get_storage_classes', content)
        self.assertIn('storageClassName', content)

    def test_script_handles_events(self):
        """Test that script checks Kubernetes events."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('get_events', content)
        self.assertIn('ProvisioningFailed', content)


class TestArgumentParsing(unittest.TestCase):
    """Test argument parsing without requiring kubectl."""

    def test_help_contains_examples(self):
        """Test that help output includes practical examples."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('Examples:', stdout)
        self.assertIn('k8s_pvc_stuck_detector.py', stdout)

    def test_help_shows_default_threshold(self):
        """Test that help shows default threshold value."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('default', stdout.lower())
        self.assertIn('5', stdout)  # Default threshold is 5 minutes

    def test_threshold_with_format_json(self):
        """Test combining threshold and JSON format."""
        returncode, stdout, stderr = run_command(['--threshold', '60', '--format', 'json'])
        self.assertIn(returncode, [1, 2])

    def test_all_options_together(self):
        """Test all options combined."""
        returncode, stdout, stderr = run_command([
            '-t', '120',
            '-n', 'monitoring',
            '-f', 'table',
            '-v'
        ])
        self.assertIn(returncode, [1, 2])


class TestTimeFunctions(unittest.TestCase):
    """Test time-related functionality in the script."""

    def test_script_has_duration_formatting(self):
        """Test that script formats durations."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('def format_duration', content)
        # Should handle hours and days
        self.assertIn('1440', content)  # minutes in a day

    def test_script_has_timestamp_parsing(self):
        """Test that script parses Kubernetes timestamps."""
        with open('k8s_pvc_stuck_detector.py', 'r') as f:
            content = f.read()
        self.assertIn('def parse_k8s_timestamp', content)
        self.assertIn('creationTimestamp', content)


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
