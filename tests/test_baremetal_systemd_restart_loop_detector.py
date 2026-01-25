#!/usr/bin/env python3
"""
Tests for baremetal_systemd_restart_loop_detector.py

These tests verify the script's argument parsing and basic functionality
without requiring actual systemd services or root access.
"""

import json
import os
import subprocess
import sys
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


class TestBaremetalSystemdRestartLoopDetector(unittest.TestCase):
    """Test cases for baremetal_systemd_restart_loop_detector.py"""

    @classmethod
    def setUpClass(cls):
        """Change to script directory before running tests."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(script_dir)
        cls.script_path = os.path.join(
            script_dir, 'baremetal_systemd_restart_loop_detector.py'
        )

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
        self.assertIn('restart loop', content.lower(),
                      "Docstring should mention restart loop")

    def test_script_has_exit_codes_documented(self):
        """Verify the script documents exit codes."""
        with open(self.script_path, 'r') as f:
            content = f.read()
        self.assertIn('Exit codes:', content,
                      "Script should document exit codes")

    def test_help_message(self):
        """Test that --help flag works and shows usage information."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--help'
        ])

        self.assertEqual(return_code, 0, "Help should return exit code 0")
        self.assertIn('restart loop', stdout.lower(),
                      "Help should contain description")
        self.assertIn('--format', stdout, "Help should document --format option")
        self.assertIn('--verbose', stdout, "Help should document --verbose option")
        self.assertIn('--threshold', stdout, "Help should document --threshold")
        self.assertIn('--hours', stdout, "Help should document --hours")
        self.assertIn('--all', stdout, "Help should document --all")
        self.assertIn('Examples:', stdout, "Help should include examples")
        self.assertIn('Exit codes:', stdout, "Help should document exit codes")

    def test_format_plain(self):
        """Test that --format plain is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain'
        ])

        # Should succeed or fail gracefully (systemctl might not be available)
        self.assertNotIn('invalid choice', stderr.lower(),
                         "Plain format should be valid")

    def test_format_json(self):
        """Test that --format json is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json'
        ])

        self.assertNotIn('invalid choice', stderr.lower(),
                         "JSON format should be valid")

    def test_format_table(self):
        """Test that --format table is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table'
        ])

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

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "Verbose flag should be recognized")

    def test_custom_threshold(self):
        """Test that custom threshold option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--threshold', '10'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "Threshold option should be recognized")

    def test_custom_hours(self):
        """Test that custom hours option works."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--hours', '6'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "Hours option should be recognized")

    def test_fractional_hours(self):
        """Test that fractional hours are accepted."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--hours', '0.5'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "Fractional hours should be accepted")
        self.assertNotIn('invalid', stderr.lower(),
                         "Fractional hours should be valid")

    def test_invalid_threshold_zero(self):
        """Test that zero threshold is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--threshold', '0'
        ])

        self.assertEqual(return_code, 2,
                         "Zero threshold should return exit code 2")
        self.assertIn('threshold', stderr.lower(),
                      "Should show error about threshold")

    def test_invalid_threshold_negative(self):
        """Test that negative threshold is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--threshold', '-5'
        ])

        self.assertEqual(return_code, 2,
                         "Negative threshold should return exit code 2")

    def test_invalid_hours_zero(self):
        """Test that zero hours is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--hours', '0'
        ])

        self.assertEqual(return_code, 2,
                         "Zero hours should return exit code 2")
        self.assertIn('hours', stderr.lower(),
                      "Should show error about hours")

    def test_invalid_hours_negative(self):
        """Test that negative hours is rejected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--hours', '-1'
        ])

        self.assertEqual(return_code, 2,
                         "Negative hours should return exit code 2")

    def test_all_flag(self):
        """Test that --all flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--all'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "All flag should be recognized")

    def test_warn_only_flag(self):
        """Test that --warn-only flag is recognized."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--warn-only'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "Warn-only flag should be recognized")

    def test_combined_options(self):
        """Test that multiple options can be used together."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json',
            '--verbose',
            '--threshold', '5',
            '--hours', '2',
            '--all'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "Combined options should work together")

    def test_short_options(self):
        """Test that short option flags work."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '-f', 'json',
            '-v',
            '-t', '5',
            '-H', '2',
            '-a'
        ])

        self.assertNotIn('unrecognized arguments', stderr.lower(),
                         "Short options should be recognized")

    def test_json_output_valid(self):
        """Test that JSON output is valid JSON when systemctl is available."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'json'
        ])

        # Skip if systemctl not available
        if return_code == 2 and 'systemctl not found' in stderr:
            self.skipTest("systemctl not available")

        try:
            data = json.loads(stdout)
            self.assertIn('summary', data, "JSON should have summary key")
            self.assertIn('services', data, "JSON should have services key")
            self.assertIn('time_window_hours', data['summary'],
                          "Summary should have time_window_hours")
            self.assertIn('restart_threshold', data['summary'],
                          "Summary should have restart_threshold")
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON output: {e}\nOutput was: {stdout[:200]}")

    def test_plain_output_structure(self):
        """Test that plain output has expected structure."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'plain'
        ])

        # Skip if systemctl not available
        if return_code == 2 and 'systemctl not found' in stderr:
            self.skipTest("systemctl not available")

        self.assertIn('Systemd Service Restart Loop Detector', stdout,
                      "Output should have title")
        self.assertIn('Time window:', stdout,
                      "Output should show time window")
        self.assertIn('Restart threshold:', stdout,
                      "Output should show threshold")

    def test_table_output_structure(self):
        """Test that table output has expected structure."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--format', 'table'
        ])

        # Skip if systemctl not available
        if return_code == 2 and 'systemctl not found' in stderr:
            self.skipTest("systemctl not available")

        self.assertIn('SERVICE', stdout, "Table should have SERVICE header")
        self.assertIn('RESTARTS', stdout, "Table should have RESTARTS header")

    def test_script_imports(self):
        """Verify the script imports necessary modules."""
        with open(self.script_path, 'r') as f:
            content = f.read()

        required_imports = ['argparse', 'json', 'sys', 'subprocess']
        for module in required_imports:
            self.assertIn(f'import {module}', content,
                          f"Script should import {module}")

    def test_exit_code_zero_when_no_loops(self):
        """Test exit code is 0 when no restart loops detected."""
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path,
            '--threshold', '999'  # Very high threshold
        ])

        # Skip if systemctl not available
        if return_code == 2 and 'systemctl not found' in stderr:
            self.skipTest("systemctl not available")

        # With a very high threshold, we should get exit code 0
        self.assertEqual(return_code, 0,
                         "Should return 0 when no loops detected with high threshold")

    def test_systemctl_not_found_handling(self):
        """Test graceful handling when systemctl is missing."""
        # This test verifies the error message format if systemctl is unavailable
        # On systems with systemctl, this test implicitly passes
        return_code, stdout, stderr = run_command([
            sys.executable,
            self.script_path
        ])

        if 'systemctl not found' in stderr:
            self.assertEqual(return_code, 2,
                             "Missing systemctl should return exit code 2")
            self.assertIn('systemd', stderr.lower(),
                          "Error should mention systemd requirement")


def main():
    """Run all tests using unittest."""
    unittest.main(argv=[''], verbosity=2, exit=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
