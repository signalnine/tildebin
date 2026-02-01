"""Tests for disk_space_forecaster script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "df"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestDiskSpaceForecaster:
    """Tests for disk_space_forecaster."""

    def test_healthy_filesystems(self, mock_context):
        """All filesystems healthy returns exit code 0."""
        from scripts.baremetal.disk_space_forecaster import run

        ctx = mock_context(
            command_outputs={
                ("df", "-B1", "--output=source,target,size,used,avail,pcent"): load_fixture("df_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 0
        assert output.data["summary"]["ok"] == 3
        assert output.data["summary"]["critical"] == 0
        assert output.data["summary"]["warning"] == 0

    def test_warning_threshold(self, mock_context):
        """Filesystems at 80%+ return warning (exit code 1)."""
        from scripts.baremetal.disk_space_forecaster import run

        ctx = mock_context(
            command_outputs={
                ("df", "-B1", "--output=source,target,size,used,avail,pcent"): load_fixture("df_warning.txt"),
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["summary"]["warning"] >= 1

    def test_critical_threshold(self, mock_context):
        """Filesystems at 95%+ return critical (exit code 1)."""
        from scripts.baremetal.disk_space_forecaster import run

        ctx = mock_context(
            command_outputs={
                ("df", "-B1", "--output=source,target,size,used,avail,pcent"): load_fixture("df_critical.txt"),
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 1
        assert output.data["summary"]["critical"] >= 1

    def test_custom_thresholds(self, mock_context):
        """Custom thresholds are respected."""
        from scripts.baremetal.disk_space_forecaster import run

        ctx = mock_context(
            command_outputs={
                ("df", "-B1", "--output=source,target,size,used,avail,pcent"): load_fixture("df_warning.txt"),
            },
        )
        output = Output()

        # With higher thresholds, 80% should be OK
        result = run(["--warn-pct", "90", "--crit-pct", "98"], output, ctx)

        assert result == 0
        assert output.data["summary"]["ok"] == 2

    def test_no_filesystems_found(self, mock_context):
        """Returns error when no filesystems found."""
        from scripts.baremetal.disk_space_forecaster import run

        ctx = mock_context(
            command_outputs={
                ("df", "-B1", "--output=source,target,size,used,avail,pcent"): load_fixture("df_empty.txt"),
            },
        )
        output = Output()

        result = run([], output, ctx)

        assert result == 2
        assert len(output.errors) > 0

    def test_warn_only_mode(self, mock_context):
        """--warn-only filters to only show issues."""
        from scripts.baremetal.disk_space_forecaster import run

        ctx = mock_context(
            command_outputs={
                ("df", "-B1", "--output=source,target,size,used,avail,pcent"): load_fixture("df_mixed.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, ctx)

        # Mixed has one warning filesystem
        assert result == 1
        # In warn-only mode, only warning/critical filesystems shown
        for fs in output.data["filesystems"]:
            assert fs["severity"] in ("WARNING", "CRITICAL")

    def test_verbose_output(self, mock_context):
        """--verbose includes additional fields."""
        from scripts.baremetal.disk_space_forecaster import run

        ctx = mock_context(
            command_outputs={
                ("df", "-B1", "--output=source,target,size,used,avail,pcent"): load_fixture("df_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, ctx)

        assert result == 0
        # Verbose mode includes size_bytes, used_bytes, etc.
        fs = output.data["filesystems"][0]
        assert "size_bytes" in fs
        assert "used_bytes" in fs
