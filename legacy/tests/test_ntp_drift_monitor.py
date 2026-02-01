#!/usr/bin/env python3
"""
Tests for ntp_drift_monitor.py

These tests verify the script's argument parsing and basic functionality
without requiring actual NTP/Chrony services.
"""

import subprocess
import sys
import os
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


class TestNTPDriftMonitor(unittest.TestCase):
    """Test cases for ntp_drift_monitor.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(script_dir, 'ntp_drift_monitor.py')

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
        self.assertIn('Monitor NTP', content, "Docstring should mention NTP")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('Monitor NTP', stdout, "Help should contain description")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--warn-threshold', stdout, "Help should document --warn-threshold")
        self.assertIn('--crit-threshold', stdout, "Help should document --crit-threshold")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain'
        ])

        # Script should run (may exit with 2 if ntp/chrony not available, which is OK)
        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "Plain format should be valid")

    def test_format_json(self):
        """Test that --format json is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('invalid choice', stderr.lower(),
                        "JSON format should be valid")

    def test_format_table(self):
        """Test that --format table is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table'
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
            '--verbose'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Verbose flag should be recognized")

    def test_custom_thresholds(self):
        """Test that custom threshold options work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-threshold', '0.050',
            '--crit-threshold', '0.500'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Threshold options should be recognized")

    def test_invalid_threshold_order(self):
        """Test that warn threshold >= crit threshold is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-threshold', '1.0',
            '--crit-threshold', '0.5'
        ])

        self.assertEqual(return_code, 2,
                        "Invalid threshold order should return exit code 2")
        self.assertIn('threshold', stderr.lower(),
                     "Should show error about thresholds")

    def test_negative_threshold(self):
        """Test that negative thresholds are rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-threshold', '-0.1'
        ])

        self.assertEqual(return_code, 2,
                        "Negative threshold should return exit code 2")
        self.assertIn('threshold', stderr.lower(),
                     "Should show error about thresholds")

    def test_zero_threshold(self):
        """Test that zero thresholds are rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-threshold', '0.0'
        ])

        self.assertEqual(return_code, 2,
                        "Zero threshold should return exit code 2")
        self.assertIn('positive', stderr.lower(),
                     "Should show error about positive numbers")

    def test_combined_options(self):
        """Test that multiple options can be used together."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--verbose',
            '--warn-threshold', '0.050',
            '--crit-threshold', '0.500'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Combined options should work together")

    def test_no_ntp_chrony_handling(self):
        """Test graceful handling when neither NTP nor Chrony is available."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path
        ])

        # Should either work (0, 1) or report missing dependencies (2)
        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")

        # If neither ntp nor chrony found, should have helpful error message
        if return_code == 2:
            stderr_lower = stderr.lower()
            if 'chrony' in stderr_lower or 'ntp' in stderr_lower:
                self.assertTrue('install' in stderr_lower or 'apt' in stderr_lower or 'yum' in stderr_lower,
                              "Should provide installation instructions")

    def test_short_options(self):
        """Test that short option flags work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '-f', 'json',
            '-v'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Short options should be recognized")

    def test_script_imports(self):
        """Verify the script imports necessary modules."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        required_imports = ['argparse', 'json', 'subprocess', 'sys', 're']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                         f"Script should import {module}")


def main():
    """Run all tests using unittest."""
    # Run with verbose output
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
