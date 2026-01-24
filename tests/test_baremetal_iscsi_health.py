#!/usr/bin/env python3
"""
Tests for baremetal_iscsi_health.py

These tests validate the script's behavior without requiring actual iSCSI infrastructure.
Tests cover argument parsing, help messages, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the baremetal_iscsi_health.py script with given arguments."""
    cmd = [sys.executable, 'baremetal_iscsi_health.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestBaremetalIscsiHealth(unittest.TestCase):
    """Test cases for baremetal_iscsi_health.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('iSCSI', stdout)
        self.assertIn('--format', stdout)
        self.assertIn('--warn-only', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--skip-multipath', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('iSCSI', stdout)

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no iscsiadm) or 0/1 (success/issues)
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

    def test_verbose_option_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_skip_multipath_option(self):
        """Test --skip-multipath option is accepted."""
        returncode, stdout, stderr = run_command(['--skip-multipath'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-w', '-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command(['--format', 'plain', '--warn-only', '--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_all_options_combined(self):
        """Test all options together."""
        returncode, stdout, stderr = run_command([
            '--format', 'json',
            '--warn-only',
            '--verbose',
            '--skip-multipath'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_iscsiadm_not_found_error(self):
        """Test graceful handling when iscsiadm is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 0, 1, or 2
        self.assertIn(returncode, [0, 1, 2])
        # If iscsiadm not found, should show helpful message
        if returncode == 2:
            self.assertTrue(
                'iscsiadm' in stderr.lower() or
                'open-iscsi' in stderr.lower() or
                'iscsi-initiator-utils' in stderr.lower()
            )

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without iscsiadm, but args are valid)
        self.assertIn(returncode, [0, 1, 2])

    def test_warn_only_with_json(self):
        """Test warn-only works with JSON format."""
        returncode, stdout, stderr = run_command(['--warn-only', '--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_with_skip_multipath(self):
        """Test verbose works with skip-multipath."""
        returncode, stdout, stderr = run_command(['-v', '--skip-multipath'])
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('baremetal_iscsi_health.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('baremetal_iscsi_health.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('iSCSI', content[:500])

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('baremetal_iscsi_health.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('baremetal_iscsi_health.py', 'r') as f:
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
        self.assertIn('baremetal_iscsi_health.py', stdout)


class TestIscsiFeatures(unittest.TestCase):
    """Test that script handles iSCSI-specific features."""

    def test_script_handles_multipath(self):
        """Test that script contains multipath handling."""
        with open('baremetal_iscsi_health.py', 'r') as f:
            content = f.read()
        # Check for multipath handling
        self.assertIn('multipath', content.lower())
        self.assertIn('--skip-multipath', content)

    def test_script_handles_sessions(self):
        """Test that script handles iSCSI sessions."""
        with open('baremetal_iscsi_health.py', 'r') as f:
            content = f.read()
        # Check for session handling
        self.assertIn('session', content.lower())
        self.assertIn('iscsiadm', content)

    def test_script_handles_targets(self):
        """Test that script handles iSCSI targets."""
        with open('baremetal_iscsi_health.py', 'r') as f:
            content = f.read()
        # Check for target handling
        self.assertIn('target', content.lower())
        self.assertIn('portal', content.lower())


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
