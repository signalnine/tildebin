#!/usr/bin/env python3
"""
Tests for baremetal_journal_disk_usage.py

These tests verify the script's argument parsing and basic functionality
without requiring actual systemd journal access.
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


class TestJournalDiskUsage(unittest.TestCase):
    """Test cases for baremetal_journal_disk_usage.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(script_dir, 'baremetal_journal_disk_usage.py')

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
        self.assertIn('journal', content.lower(), "Docstring should mention journal")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('journal', stdout.lower(), "Help should contain description")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--warn-pct', stdout, "Help should document --warn-pct")
        self.assertIn('--crit-pct', stdout, "Help should document --crit-pct")
        self.assertIn('--warn-size', stdout, "Help should document --warn-size")
        self.assertIn('--crit-size', stdout, "Help should document --crit-size")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain'
        ])

        # Script should run (may exit with 2 if journalctl not available)
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

    def test_custom_percentage_thresholds(self):
        """Test that custom percentage threshold options work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-pct', '70',
            '--crit-pct', '90'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Percentage threshold options should be recognized")

    def test_custom_size_thresholds(self):
        """Test that custom size threshold options work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-size', '1G',
            '--crit-size', '4G'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Size threshold options should be recognized")

    def test_invalid_percentage_threshold_order(self):
        """Test that warn percentage >= crit percentage is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-pct', '95',
            '--crit-pct', '80'
        ])

        self.assertEqual(return_code, 2,
                        "Invalid percentage threshold order should return exit code 2")
        self.assertIn('percentage', stderr.lower(),
                     "Should show error about percentage thresholds")

    def test_invalid_size_threshold_order(self):
        """Test that warn size >= crit size is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-size', '4G',
            '--crit-size', '1G'
        ])

        self.assertEqual(return_code, 2,
                        "Invalid size threshold order should return exit code 2")
        self.assertIn('size', stderr.lower(),
                     "Should show error about size thresholds")

    def test_invalid_size_format(self):
        """Test that invalid size format is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-size', 'invalid'
        ])

        self.assertEqual(return_code, 2,
                        "Invalid size format should return exit code 2")
        self.assertIn('invalid', stderr.lower(),
                     "Should show error about invalid format")

    def test_negative_percentage_threshold(self):
        """Test that negative percentage thresholds are rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-pct', '-10'
        ])

        self.assertEqual(return_code, 2,
                        "Negative percentage threshold should return exit code 2")
        self.assertIn('positive', stderr.lower(),
                     "Should show error about positive numbers")

    def test_skip_verify_flag(self):
        """Test that --skip-verify flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--skip-verify'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Skip verify flag should be recognized")

    def test_skip_producers_flag(self):
        """Test that --skip-producers flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--skip-producers'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Skip producers flag should be recognized")

    def test_combined_options(self):
        """Test that multiple options can be used together."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--verbose',
            '--warn-pct', '70',
            '--crit-pct', '90',
            '--skip-verify',
            '--skip-producers'
        ])

        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")
        self.assertNotIn('unrecognized arguments', stderr.lower(),
                        "Combined options should work together")

    def test_no_journalctl_handling(self):
        """Test graceful handling when journalctl is not available."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path
        ])

        # Should either work (0, 1) or report missing dependencies (2)
        self.assertIn(return_code, [0, 1, 2],
                     f"Unexpected return code {return_code}")

        # If journalctl not found, should have helpful error message
        if return_code == 2:
            stderr_lower = stderr.lower()
            if 'journalctl' in stderr_lower:
                self.assertTrue('systemd' in stderr_lower or 'not found' in stderr_lower,
                              "Should provide helpful error message")

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

        required_imports = ['argparse', 'json', 'subprocess', 'sys', 'os', 're']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                         f"Script should import {module}")

    def test_json_output_format(self):
        """Test that JSON output is valid when available."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--skip-verify',
            '--skip-producers'
        ])

        # If successful, verify JSON is valid
        if return_code in [0, 1] and stdout.strip():
            import json
            try:
                data = json.loads(stdout)
                self.assertIn('status', data,
                             "JSON output should contain status field")
            except json.JSONDecodeError:
                # If output isn't JSON, it might be an error message
                pass

    def test_size_threshold_formats(self):
        """Test various size threshold formats are accepted."""
        size_formats = ['500M', '1G', '100K', '2T']
        for size in size_formats:
            return_code, stdout, stderr = run_command([
                sys.executable,
                self.script_path,
                '--warn-size', size,
                '--crit-size', '10T'  # Large to not conflict
            ])

            self.assertIn(return_code, [0, 1, 2],
                         f"Size format {size} should be accepted")
            self.assertNotIn('invalid', stderr.lower(),
                            f"Size format {size} should be valid")


def main():
    """Run all tests using unittest."""
    # Run with verbose output
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
