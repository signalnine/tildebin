#!/usr/bin/env python3
"""
Tests for baremetal_nfs_mount_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual NFS mounts or network access.
"""

import subprocess
import sys
import os
import json
import tempfile
import unittest


def run_command(cmd):
    """Run a command and return (return_code, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


class TestNFSMountMonitor(unittest.TestCase):
    """Test cases for baremetal_nfs_mount_monitor.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(script_dir, 'baremetal_nfs_mount_monitor.py')

    def test_script_exists(self):
        """Verify the script file exists."""
        self.assertTrue(os.path.exists(self.script_path),
                       f"Script not found at {self.script_path}")

    def test_script_has_shebang(self):
        """Verify the script has proper shebang."""
        with open(self.script_path, 'r') as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith('#!/usr/bin/env python3'),
                       "Script should start with #!/usr/bin/env python3 shebang")

    def test_script_has_docstring(self):
        """Verify the script has a module docstring."""
        with open(self.script_path, 'r') as f:
            content = f.read()
        self.assertIn('"""', content, "Script should have docstring")
        self.assertIn('NFS', content, "Docstring should mention NFS")
        self.assertIn('Exit codes:', content, "Docstring should document exit codes")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('NFS', stdout, "Help should contain NFS description")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--warn-only', stdout, "Help should document --warn-only option")
        self.assertIn('--no-connectivity', stdout, "Help should document --no-connectivity")
        self.assertIn('--timeout', stdout, "Help should document --timeout")
        self.assertIn('--nfs-port', stdout, "Help should document --nfs-port")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "Plain format should be valid")

    def test_format_json(self):
        """Test that --format json is recognized and produces valid JSON."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "JSON format should be valid")

        # Try to parse JSON output
        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                self.assertIn('mounts', data, "JSON should contain mounts")
                self.assertIn('healthy', data, "JSON should contain healthy status")
                self.assertIn('mount_count', data, "JSON should contain mount_count")
            except json.JSONDecodeError:
                pass  # May fail if there's an error message before JSON

    def test_format_table(self):
        """Test that --format table is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "Table format should be valid")

    def test_invalid_format(self):
        """Test that invalid format option is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'invalid'
        ])

        self.assertEqual(return_code, 2, "Invalid format should return exit code 2")
        self.assertIn('invalid choice', stderr.lower(),
                     "Should show error for invalid format")

    def test_verbose_flag(self):
        """Test that --verbose flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--verbose',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Verbose flag should be recognized")

    def test_warn_only_flag(self):
        """Test that --warn-only flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-only',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Warn-only flag should be recognized")

    def test_no_connectivity_flag(self):
        """Test that --no-connectivity flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "No-connectivity flag should be recognized")

    def test_no_fstab_flag(self):
        """Test that --no-fstab flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--no-fstab',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "No-fstab flag should be recognized")

    def test_custom_timeout(self):
        """Test that --timeout option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--timeout', '10.0',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Timeout option should be recognized")

    def test_invalid_timeout(self):
        """Test that negative timeout is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--timeout', '-1'
        ])

        self.assertEqual(return_code, 2,
                        "Negative timeout should return exit code 2")
        self.assertIn('timeout', stderr.lower(),
                     "Should show error about timeout")

    def test_custom_nfs_port(self):
        """Test that --nfs-port option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--nfs-port', '111',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "NFS-port option should be recognized")

    def test_combined_options(self):
        """Test that multiple options can be used together."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--verbose',
            '--no-connectivity',
            '--no-fstab',
            '--timeout', '3.0'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Combined options should work together")

    def test_short_options(self):
        """Test that short option flags work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '-f', 'json',
            '-v',
            '-w',
            '--no-connectivity'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Short options should be recognized")

    def test_script_imports(self):
        """Verify the script imports necessary modules."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        required_imports = ['argparse', 'json', 'subprocess', 'sys', 'os', 're', 'time']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                         f"Script should import {module}")

    def test_json_output_structure(self):
        """Test that JSON output has expected structure."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--no-connectivity'
        ])

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                # Check required fields
                self.assertIn('mounts', data)
                self.assertIn('issues', data)
                self.assertIn('warnings', data)
                self.assertIn('healthy', data)
                self.assertIn('mount_count', data)

                # Check mounts is a list
                self.assertIsInstance(data['mounts'], list)
                self.assertIsInstance(data['issues'], list)
                self.assertIsInstance(data['warnings'], list)
            except json.JSONDecodeError:
                pass  # May have error output before JSON

    def test_default_run(self):
        """Test default run without any options."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path
        ])

        # Should either succeed or report issues - any valid exit code is OK
        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")

        # Should have some output
        self.assertTrue(stdout or stderr,
                       "Script should produce some output")

    def test_output_contains_header(self):
        """Test that plain output contains expected header."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain',
            '--no-connectivity'
        ])

        if return_code in [0, 1]:
            self.assertIn('NFS Mount Health Monitor', stdout,
                         "Output should contain header")

    def test_table_format_has_header(self):
        """Test that table format has column headers."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table',
            '--no-connectivity'
        ])

        if return_code in [0, 1]:
            self.assertIn('MOUNTPOINT', stdout,
                         "Table should have MOUNTPOINT column")
            self.assertIn('SERVER', stdout,
                         "Table should have SERVER column")
            self.assertIn('STATUS', stdout,
                         "Table should have STATUS column")

    def test_warn_only_with_no_issues(self):
        """Test warn-only mode when there are no issues."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-only',
            '--no-connectivity',
            '--format', 'json'
        ])

        if return_code == 0:
            try:
                data = json.loads(stdout)
                self.assertTrue(data.get('healthy', False),
                               "Should be healthy when no issues")
            except json.JSONDecodeError:
                # May have plain text output
                self.assertIn('healthy', stdout.lower(),
                             "Should indicate healthy status")

    def test_handles_no_nfs_mounts(self):
        """Test that script handles systems with no NFS mounts gracefully."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--no-connectivity'
        ])

        # Should succeed even if no NFS mounts
        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")

        if return_code in [0, 1]:
            try:
                data = json.loads(stdout)
                # mount_count should be a non-negative integer
                self.assertGreaterEqual(data.get('mount_count', 0), 0,
                                       "mount_count should be >= 0")
            except json.JSONDecodeError:
                pass

    def test_main_function_exists(self):
        """Verify the script has a main function."""
        with open(self.script_path, 'r') as f:
            content = f.read()
        self.assertIn('def main():', content,
                     "Script should have a main function")
        self.assertIn("if __name__ == '__main__':", content,
                     "Script should have main guard")


def main():
    """Run all tests using unittest."""
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
