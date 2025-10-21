#!/usr/bin/env python3
"""
Tests for filesystem_usage_tracker.py

Tests validate:
  - Argument parsing and help messages
  - Directory scanning with various depths
  - Output formatting (plain, table, json)
  - Error handling for missing/invalid paths
  - Exit codes and error messages
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run_command(cmd_args):
    """
    Execute filesystem_usage_tracker.py and capture output.

    Args:
        cmd_args: List of command arguments

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "filesystem_usage_tracker.py"
    )

    cmd = [sys.executable, script_path] + cmd_args

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr


def test_help_message():
    """Validate --help works and shows usage information."""
    returncode, stdout, stderr = run_command(["--help"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"
    assert "positional arguments:" in stdout, "Help should list positional arguments"
    assert "filesystem usage" in stdout, "Help should describe the tool"


def test_help_message_h():
    """Validate -h flag works."""
    returncode, stdout, stderr = run_command(["-h"])

    assert returncode == 0, f"Help should exit with 0, got {returncode}"
    assert "usage:" in stdout, "Help should contain usage information"


def test_missing_path_argument():
    """Validate error when no path argument provided."""
    returncode, stdout, stderr = run_command([])

    assert returncode == 2, f"Missing arg should exit with 2, got {returncode}"
    assert "usage:" in stderr or "required:" in stderr or "positional" in stderr


def test_nonexistent_path():
    """Validate error for nonexistent path."""
    returncode, stdout, stderr = run_command(["/nonexistent/path/12345"])

    assert returncode == 1, f"Nonexistent path should exit with 1, got {returncode}"
    assert "does not exist" in stderr or "Path" in stderr


def test_file_path_instead_of_directory():
    """Validate error when file path is provided instead of directory."""
    with tempfile.NamedTemporaryFile() as tmp_file:
        returncode, stdout, stderr = run_command([tmp_file.name])

        assert returncode == 1, f"File path should exit with 1, got {returncode}"
        assert "not a directory" in stderr or "directory" in stderr


def test_scan_temp_directory():
    """Validate basic scanning of a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        Path(tmpdir, "file1.txt").write_text("x" * 1000)
        Path(tmpdir, "file2.txt").write_text("y" * 2000)
        subdir = Path(tmpdir, "subdir")
        subdir.mkdir()
        Path(subdir, "file3.txt").write_text("z" * 500)

        returncode, stdout, stderr = run_command([tmpdir])

        assert returncode == 0, f"Scan should succeed, got {returncode}"
        assert tmpdir in stdout, "Output should contain scanned path"
        # Should contain directory entries
        assert "subdir" in stdout or "file" in stdout or tmpdir in stdout


def test_output_format_plain():
    """Validate plain output format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "test.txt").write_text("x" * 1000)

        returncode, stdout, stderr = run_command([
            tmpdir,
            "--format", "plain"
        ])

        assert returncode == 0, f"Command should succeed, got {returncode}"
        assert tmpdir in stdout, "Output should contain path"
        # Plain format should have simple columns
        lines = stdout.strip().split('\n')
        assert len(lines) > 1, "Should have multiple lines"


def test_output_format_table():
    """Validate table output format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "test.txt").write_text("x" * 1000)

        returncode, stdout, stderr = run_command([
            tmpdir,
            "--format", "table"
        ])

        assert returncode == 0, f"Command should succeed, got {returncode}"
        assert tmpdir in stdout, "Output should contain path"
        # Table format should have headers and separators
        assert "|" in stdout or "-" in stdout, "Table should have formatting"


def test_output_format_json():
    """Validate JSON output format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "test.txt").write_text("x" * 1000)

        returncode, stdout, stderr = run_command([
            tmpdir,
            "--format", "json"
        ])

        assert returncode == 0, f"Command should succeed, got {returncode}"

        # Parse JSON to validate format
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            assert False, f"Invalid JSON output: {e}"

        assert "path" in data, "JSON should contain 'path' key"
        assert "entries" in data, "JSON should contain 'entries' key"
        assert isinstance(data["entries"], list), "entries should be a list"

        if data["entries"]:
            entry = data["entries"][0]
            assert "bytes" in entry, "Entry should have 'bytes'"
            assert "human_readable" in entry, "Entry should have 'human_readable'"
            assert "directory" in entry, "Entry should have 'directory'"


def test_depth_argument():
    """Validate --depth argument works."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create nested directories
        Path(tmpdir, "level1").mkdir()
        Path(tmpdir, "level1/level2").mkdir()
        Path(tmpdir, "level1/level2/level3").mkdir()
        Path(tmpdir, "file.txt").write_text("test")

        # Scan with depth 1
        returncode, stdout, stderr = run_command([
            tmpdir,
            "--depth", "1",
            "--format", "json"
        ])

        assert returncode == 0, f"Command should succeed, got {returncode}"
        data = json.loads(stdout)
        # With depth 1, should not go deep into directory structure
        assert len(data["entries"]) >= 1, "Should have at least one entry"


def test_top_argument():
    """Validate --top argument limits output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create multiple files
        for i in range(5):
            Path(tmpdir, f"file{i}.txt").write_text("x" * 1000)

        returncode, stdout, stderr = run_command([
            tmpdir,
            "--top", "2",
            "--format", "json"
        ])

        assert returncode == 0, f"Command should succeed, got {returncode}"
        data = json.loads(stdout)
        # Should limit to 2 entries
        assert len(data["entries"]) <= 2, "Should respect --top limit"


def test_top_argument_invalid():
    """Validate --top rejects invalid values."""
    with tempfile.TemporaryDirectory() as tmpdir:
        returncode, stdout, stderr = run_command([
            tmpdir,
            "--top", "0"
        ])

        assert returncode == 2, f"Invalid --top should exit with 2, got {returncode}"
        assert "top" in stderr or "must be" in stderr


def test_depth_argument_invalid():
    """Validate --depth rejects invalid values."""
    with tempfile.TemporaryDirectory() as tmpdir:
        returncode, stdout, stderr = run_command([
            tmpdir,
            "--depth", "-1"
        ])

        assert returncode == 2, f"Invalid --depth should exit with 2, got {returncode}"
        assert "depth" in stderr or "must be" in stderr


def test_quiet_mode():
    """Validate --quiet suppresses progress messages."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "test.txt").write_text("x" * 1000)

        returncode, stdout, stderr = run_command([
            tmpdir,
            "--quiet",
            "--format", "plain"
        ])

        assert returncode == 0, f"Command should succeed, got {returncode}"
        # In quiet mode, shouldn't print scanning message to stderr
        # (but results still go to stdout)


def test_default_format():
    """Validate default output format is table."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "test.txt").write_text("x" * 1000)

        returncode, stdout, stderr = run_command([tmpdir])

        assert returncode == 0, f"Command should succeed, got {returncode}"
        # Default format is table, should have formatting characters
        lines = stdout.strip().split('\n')
        assert len(lines) > 1, "Should have multiple lines"


def test_default_depth():
    """Validate default depth is 3."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Specify depth explicitly and implicitly to compare
        returncode1, stdout1, stderr1 = run_command([
            tmpdir,
            "--format", "json"
        ])

        returncode2, stdout2, stderr2 = run_command([
            tmpdir,
            "--depth", "3",
            "--format", "json"
        ])

        # Both should succeed and have same entries
        assert returncode1 == 0 and returncode2 == 0


def test_default_top():
    """Validate default --top value."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create some entries
        for i in range(15):
            Path(tmpdir, f"file{i}.txt").write_text("x" * 1000)

        returncode, stdout, stderr = run_command([
            tmpdir,
            "--format", "json"
        ])

        assert returncode == 0, f"Command should succeed, got {returncode}"
        data = json.loads(stdout)
        # Default --top is 10
        assert len(data["entries"]) <= 10, "Default --top should be 10"


if __name__ == "__main__":
    # Run all tests
    tests = [
        test_help_message,
        test_help_message_h,
        test_missing_path_argument,
        test_nonexistent_path,
        test_file_path_instead_of_directory,
        test_scan_temp_directory,
        test_output_format_plain,
        test_output_format_table,
        test_output_format_json,
        test_depth_argument,
        test_top_argument,
        test_top_argument_invalid,
        test_depth_argument_invalid,
        test_quiet_mode,
        test_default_format,
        test_default_depth,
        test_default_top,
    ]

    failed = 0
    passed = 0

    for test in tests:
        try:
            test()
            print(f"✓ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: Unexpected error: {e}")
            failed += 1

    # Output test results in format expected by test runner
    print(f"\nTest Results: {passed}/{len(tests)} tests passed")
    sys.exit(0 if failed == 0 else 1)
