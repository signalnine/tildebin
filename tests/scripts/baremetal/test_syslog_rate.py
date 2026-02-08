"""Tests for syslog_rate script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "log"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSyslogRate:
    """Tests for syslog_rate."""

    def test_normal_rate(self, capsys):
        """Normal message rate returns exit code 0."""
        from scripts.baremetal.syslog_rate import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                (
                    "journalctl",
                    "--since",
                    "5 minutes ago",
                    "--no-pager",
                    "-o",
                    "json",
                    "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY",
                ): load_fixture("journalctl_stats_json.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total Count" in captured.out

    def test_high_rate_warning(self, capsys):
        """High message rate triggers warning (exit code 1)."""
        from scripts.baremetal.syslog_rate import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                (
                    "journalctl",
                    "--since",
                    "1 minutes ago",
                    "--no-pager",
                    "-o",
                    "json",
                    "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY",
                ): load_fixture("journalctl_stats_high_rate.txt"),
            },
        )
        output = Output()

        # Low threshold to trigger warning (22 messages in 1 minute from myapp)
        result = run(["--since", "1", "--threshold", "10"], output, context)

        assert result == 1
        assert output.data["has_issues"] is True
        assert len(output.data["high_rate_sources"]) > 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.syslog_rate import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                (
                    "journalctl",
                    "--since",
                    "5 minutes ago",
                    "--no-pager",
                    "-o",
                    "json",
                    "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY",
                ): load_fixture("journalctl_stats_json.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_count" in data
        assert "rate_per_minute" in data
        assert "top_sources" in data
        assert "high_rate_sources" in data
        assert "priority_summary" in data

    def test_missing_journalctl(self, capsys):
        """Missing journalctl returns exit code 2."""
        from scripts.baremetal.syslog_rate import run

        context = MockContext(
            tools_available=[],  # No journalctl
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_no_output_when_healthy(self, capsys):
        """With --warn-only, no output when healthy."""
        from scripts.baremetal.syslog_rate import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                (
                    "journalctl",
                    "--since",
                    "5 minutes ago",
                    "--no-pager",
                    "-o",
                    "json",
                    "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY",
                ): load_fixture("journalctl_stats_json.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_invalid_since(self, capsys):
        """Invalid --since returns exit code 2."""
        from scripts.baremetal.syslog_rate import run

        context = MockContext(tools_available=["journalctl"])
        output = Output()

        result = run(["--since", "-5"], output, context)

        assert result == 2

    def test_custom_threshold(self, capsys):
        """Custom threshold is respected."""
        from scripts.baremetal.syslog_rate import run

        context = MockContext(
            tools_available=["journalctl"],
            command_outputs={
                (
                    "journalctl",
                    "--since",
                    "5 minutes ago",
                    "--no-pager",
                    "-o",
                    "json",
                    "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY",
                ): load_fixture("journalctl_stats_json.txt"),
            },
        )
        output = Output()

        # Very high threshold means no warnings
        result = run(["--threshold", "1000"], output, context)

        assert result == 0
