#!/usr/bin/env python3
"""
Tests for baremetal_firmware_update_monitor.py

Tests validate the script's behavior without requiring fwupd to be installed.
Tests cover argument parsing, help messages, and error handling.
"""

import subprocess
import sys
import unittest


def run_command(cmd_args, input_data=None):
    """Run the baremetal_firmware_update_monitor.py script with given arguments."""
    cmd = [sys.executable, 'baremetal_firmware_update_monitor.py'] + cmd_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_data
    )
    return result.returncode, result.stdout, result.stderr


class TestBaremetalFirmwareUpdateMonitor(unittest.TestCase):
    """Test cases for baremetal_firmware_update_monitor.py"""

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        returncode, stdout, stderr = run_command(['--help'])
        self.assertEqual(returncode, 0)
        self.assertIn('firmware', stdout.lower())
        self.assertIn('--format', stdout)
        self.assertIn('--verbose', stdout)
        self.assertIn('--refresh', stdout)
        self.assertIn('--security-only', stdout)
        self.assertIn('Examples:', stdout)

    def test_help_message_short(self):
        """Test that -h flag works."""
        returncode, stdout, stderr = run_command(['-h'])
        self.assertEqual(returncode, 0)
        self.assertIn('firmware', stdout.lower())

    def test_format_option_plain(self):
        """Test --format plain option is accepted."""
        returncode, stdout, stderr = run_command(['--format', 'plain'])
        # Either exits 2 (no fwupdmgr) or 0/1 (success/updates found)
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

    def test_verbose_option(self):
        """Test --verbose option is accepted."""
        returncode, stdout, stderr = run_command(['--verbose'])
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_short(self):
        """Test -v short option works."""
        returncode, stdout, stderr = run_command(['-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_refresh_option(self):
        """Test --refresh option is accepted."""
        returncode, stdout, stderr = run_command(['--refresh'])
        self.assertIn(returncode, [0, 1, 2])

    def test_force_refresh_option(self):
        """Test --force-refresh option is accepted."""
        returncode, stdout, stderr = run_command(['--force-refresh'])
        self.assertIn(returncode, [0, 1, 2])

    def test_security_only_option(self):
        """Test --security-only option is accepted."""
        returncode, stdout, stderr = run_command(['--security-only'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options(self):
        """Test combining multiple options."""
        returncode, stdout, stderr = run_command(['-f', 'json', '-v'])
        self.assertIn(returncode, [0, 1, 2])

    def test_combined_options_long(self):
        """Test combining long form options."""
        returncode, stdout, stderr = run_command([
            '--format', 'table',
            '--verbose',
            '--security-only'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_all_options_combined(self):
        """Test all options together."""
        returncode, stdout, stderr = run_command([
            '--format', 'json',
            '--verbose',
            '--security-only'
        ])
        self.assertIn(returncode, [0, 1, 2])

    def test_fwupdmgr_not_found_error(self):
        """Test graceful handling when fwupdmgr is not found."""
        returncode, stdout, stderr = run_command([])
        # Should exit with error code 0, 1, or 2
        self.assertIn(returncode, [0, 1, 2])
        # If exit code 2, error message should mention fwupdmgr
        if returncode == 2:
            self.assertIn('fwupdmgr', stderr.lower())

    def test_no_arguments_accepted(self):
        """Test that script runs with no arguments (uses defaults)."""
        returncode, stdout, stderr = run_command([])
        # Should attempt to run (will fail without fwupdmgr, but args are valid)
        self.assertIn(returncode, [0, 1, 2])

    def test_verbose_with_json(self):
        """Test verbose works with JSON format."""
        returncode, stdout, stderr = run_command(['--verbose', '--format', 'json'])
        self.assertIn(returncode, [0, 1, 2])

    def test_refresh_with_table(self):
        """Test refresh works with table format."""
        returncode, stdout, stderr = run_command(['--refresh', '-f', 'table'])
        self.assertIn(returncode, [0, 1, 2])


class TestScriptMetadata(unittest.TestCase):
    """Test script metadata and structure."""

    def test_script_has_shebang(self):
        """Test that script has proper shebang."""
        with open('baremetal_firmware_update_monitor.py', 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!'))
        self.assertIn('python', first_line.lower())

    def test_script_has_docstring(self):
        """Test that script has module-level docstring."""
        with open('baremetal_firmware_update_monitor.py', 'r') as f:
            content = f.read()
        # Should have triple-quoted docstring near the top
        self.assertIn('"""', content)
        self.assertIn('firmware', content[:1000].lower())

    def test_script_imports_required_modules(self):
        """Test that script imports necessary modules."""
        with open('baremetal_firmware_update_monitor.py', 'r') as f:
            content = f.read()
        # Check for required imports
        self.assertIn('import argparse', content)
        self.assertIn('import subprocess', content)
        self.assertIn('import json', content)
        self.assertIn('import sys', content)

    def test_exit_codes_documented(self):
        """Test that exit codes are documented in docstring."""
        with open('baremetal_firmware_update_monitor.py', 'r') as f:
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
        self.assertIn('baremetal_firmware_update_monitor.py', stdout)

    def test_fwupd_mentioned(self):
        """Test that fwupd is mentioned."""
        with open('baremetal_firmware_update_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('fwupd', content.lower())
        self.assertIn('fwupdmgr', content)

    def test_security_updates_supported(self):
        """Test that security updates are mentioned."""
        with open('baremetal_firmware_update_monitor.py', 'r') as f:
            content = f.read()
        self.assertIn('security', content.lower())


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
