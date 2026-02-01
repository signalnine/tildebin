"""Tests for journal_disk_usage script."""

import json
import subprocess
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "log"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestJournalDiskUsage:
    """Tests for journal_disk_usage."""

    def test_normal_usage(self, capsys):
        """Normal journal usage returns exit code 0."""
        from scripts.baremetal.journal_disk_usage import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--disk-usage"): load_fixture(
                    "journalctl_disk_usage_normal.txt"
                ),
            },
            file_contents={
                "/etc/systemd/journald.conf": load_fixture("journald_conf_default.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_high_usage_warning(self, capsys):
        """High journal usage triggers warning with absolute threshold."""
        from scripts.baremetal.journal_disk_usage import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--disk-usage"): load_fixture(
                    "journalctl_disk_usage_high.txt"
                ),
            },
            file_contents={
                "/etc/systemd/journald.conf": load_fixture("journald_conf_default.txt"),
            },
        )
        output = Output()

        # Warn at 1G, high fixture is 4.2G
        result = run(["--warn-size", "1G", "--crit-size", "5G"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_critical_usage(self, capsys):
        """Critical journal usage triggers critical status."""
        from scripts.baremetal.journal_disk_usage import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--disk-usage"): load_fixture(
                    "journalctl_disk_usage_high.txt"
                ),
            },
            file_contents={
                "/etc/systemd/journald.conf": load_fixture("journald_conf_default.txt"),
            },
        )
        output = Output()

        # Critical at 2G, high fixture is 4.2G
        result = run(["--warn-size", "1G", "--crit-size", "2G"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.journal_disk_usage import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--disk-usage"): load_fixture(
                    "journalctl_disk_usage_normal.txt"
                ),
            },
            file_contents={
                "/etc/systemd/journald.conf": load_fixture("journald_conf_default.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "usage" in data
        assert "config" in data
        assert "status" in data
        assert "issues" in data

    def test_missing_journalctl(self, capsys):
        """Missing journalctl returns exit code 2."""
        from scripts.baremetal.journal_disk_usage import run

        context = MockContext(
            tools_available=[],  # No journalctl
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_no_output_when_healthy(self, capsys):
        """With --warn-only, no output when healthy."""
        from scripts.baremetal.journal_disk_usage import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--disk-usage"): load_fixture(
                    "journalctl_disk_usage_normal.txt"
                ),
            },
            file_contents={
                "/etc/systemd/journald.conf": load_fixture("journald_conf_default.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.journal_disk_usage import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                ("journalctl", "--disk-usage"): load_fixture(
                    "journalctl_disk_usage_normal.txt"
                ),
            },
            file_contents={},
        )
        output = Output()

        # Warn pct greater than crit pct is invalid
        result = run(["--warn-pct", "90", "--crit-pct", "80"], output, context)

        assert result == 2
