"""Tests for filesystem_readonly script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestFilesystemReadonly:
    """Tests for filesystem_readonly."""

    def test_all_rw_healthy(self, capsys):
        """All read-write filesystems returns exit code 0."""
        from scripts.baremetal.filesystem_readonly import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_readonly_detected(self, capsys):
        """Read-only filesystem returns exit code 1."""
        from scripts.baremetal.filesystem_readonly import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_readonly.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.filesystem_readonly import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "filesystems" in data
        assert "readonly_count" in data
        assert "status" in data

    def test_verbose_shows_all_filesystems(self, capsys):
        """Verbose mode shows all filesystems."""
        from scripts.baremetal.filesystem_readonly import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        # Should mention mount points
        assert "/home" in captured.out or "ext4" in captured.out

    def test_missing_mounts(self, capsys):
        """Missing /proc/mounts returns exit code 2."""
        from scripts.baremetal.filesystem_readonly import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
