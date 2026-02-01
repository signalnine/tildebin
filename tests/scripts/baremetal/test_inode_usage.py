"""Tests for inode_usage script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "df"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestInodeUsage:
    """Tests for inode_usage."""

    def test_healthy_inodes(self, capsys):
        """Healthy inode usage returns exit code 0."""
        from scripts.baremetal.inode_usage import run

        context = MockContext(
            command_outputs={
                ("df", "-i", "-P"): load_fixture("df_inodes_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_warning_inodes(self, capsys):
        """High inode usage returns warning (exit code 1)."""
        from scripts.baremetal.inode_usage import run

        context = MockContext(
            command_outputs={
                ("df", "-i", "-P"): load_fixture("df_inodes_warning.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_critical_inodes(self, capsys):
        """Critical inode usage returns exit code 1."""
        from scripts.baremetal.inode_usage import run

        context = MockContext(
            command_outputs={
                ("df", "-i", "-P"): load_fixture("df_inodes_critical.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.inode_usage import run

        context = MockContext(
            command_outputs={
                ("df", "-i", "-P"): load_fixture("df_inodes_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "filesystems" in data
        assert "status" in data

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.inode_usage import run

        context = MockContext(
            command_outputs={
                ("df", "-i", "-P"): load_fixture("df_inodes_warning.txt"),  # 85%
            },
        )
        output = Output()

        # With higher threshold, should be OK
        result = run(["--warn", "90", "--crit", "95"], output, context)

        assert result == 0

    def test_verbose_shows_all(self, capsys):
        """Verbose mode shows all filesystems."""
        from scripts.baremetal.inode_usage import run

        context = MockContext(
            command_outputs={
                ("df", "-i", "-P"): load_fixture("df_inodes_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "/data" in captured.out or "/home" in captured.out

    def test_df_failure(self, capsys):
        """df command failure returns exit code 2."""
        from scripts.baremetal.inode_usage import run

        context = MockContext(
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
