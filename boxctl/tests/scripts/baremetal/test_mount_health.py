"""Tests for mount_health script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestMountHealth:
    """Tests for mount_health script."""

    def test_all_mounts_healthy(self, capsys):
        """All mounts healthy returns exit code 0."""
        from scripts.baremetal.mount_health import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_healthy.txt"),
                "/proc/self/mountinfo": load_fixture("mountinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["healthy"] > 0

    def test_readonly_detected(self, capsys):
        """Read-only filesystem detected returns exit code 1."""
        from scripts.baremetal.mount_health import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_readonly.txt"),
                "/proc/self/mountinfo": load_fixture("mountinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert len(output.data["issues"]) > 0
        assert any("readonly" in i["type"] for i in output.data["issues"])

    def test_dangerous_options_with_check_options(self, capsys):
        """Dangerous mount options detected when --check-options is used."""
        from scripts.baremetal.mount_health import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_nobarrier.txt"),
                "/proc/self/mountinfo": load_fixture("mountinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--check-options"], output, context)

        assert result == 1
        assert any("nobarrier" in i["message"] for i in output.data["issues"])

    def test_no_issues_without_check_options(self, capsys):
        """Without --check-options, nobarrier is not flagged."""
        from scripts.baremetal.mount_health import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_nobarrier.txt"),
                "/proc/self/mountinfo": load_fixture("mountinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        # Without check-options, nobarrier is not flagged as an issue
        assert result == 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.mount_health import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_healthy.txt"),
                "/proc/self/mountinfo": load_fixture("mountinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "has_issues" in data
        assert "total_mounts" in data["summary"]

    def test_verbose_shows_mount_details(self, capsys):
        """Verbose mode shows mount details in JSON."""
        from scripts.baremetal.mount_health import run

        context = MockContext(
            file_contents={
                "/proc/mounts": load_fixture("mounts_healthy.txt"),
                "/proc/self/mountinfo": load_fixture("mountinfo_healthy.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json", "--verbose"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "mounts" in data
        assert len(data["mounts"]) > 0

    def test_missing_mounts_returns_error(self, capsys):
        """Missing /proc/mounts returns exit code 2."""
        from scripts.baremetal.mount_health import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0
