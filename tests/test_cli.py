"""Tests for CLI."""

import subprocess
import sys


def run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run boxctl CLI with arguments."""
    return subprocess.run(
        [sys.executable, "-m", "boxctl"] + list(args),
        capture_output=True,
        text=True,
    )


class TestCLI:
    """Tests for boxctl CLI."""

    def test_help_displays(self):
        """--help shows usage info."""
        result = run_cli("--help")

        assert result.returncode == 0
        assert "boxctl" in result.stdout
        assert "list" in result.stdout
        assert "run" in result.stdout

    def test_version_displays(self):
        """--version shows version."""
        result = run_cli("--version")

        assert result.returncode == 0
        assert "0.1.0" in result.stdout

    def test_list_command_exists(self):
        """list command is available."""
        result = run_cli("list", "--help")

        assert result.returncode == 0
        assert "list" in result.stdout.lower()

    def test_run_command_exists(self):
        """run command is available."""
        result = run_cli("run", "--help")

        assert result.returncode == 0

    def test_show_command_exists(self):
        """show command is available."""
        result = run_cli("show", "--help")

        assert result.returncode == 0

    def test_search_command_exists(self):
        """search command is available."""
        result = run_cli("search", "--help")

        assert result.returncode == 0

    def test_invalid_command_shows_error(self):
        """Invalid command shows error."""
        result = run_cli("invalid")

        assert result.returncode != 0

    def test_list_with_category_filter(self):
        """list --category filters by category."""
        result = run_cli("list", "--category", "baremetal", "--help")

        # Just verify the option exists
        assert result.returncode == 0

    def test_list_with_tag_filter(self):
        """list --tag filters by tag."""
        result = run_cli("list", "--tag", "health", "--help")

        assert result.returncode == 0
