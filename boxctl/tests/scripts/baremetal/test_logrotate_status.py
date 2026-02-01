"""Tests for logrotate_status script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "log"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestLogrotateStatus:
    """Tests for logrotate_status."""

    def test_healthy_state(self, capsys):
        """Healthy logrotate state returns exit code 0."""
        from scripts.baremetal.logrotate_status import run

        context = MockContext(
            file_contents={
                "/var/lib/logrotate/status": load_fixture("logrotate_state_healthy.txt"),
                "/var/log": "",  # Directory marker
                "/var/log/syslog": "some log content",
                "/var/log/auth.log": "auth log content",
                "/var/log/kern.log": "kern log content",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No logrotate issues detected" in captured.out

    def test_stale_logs_warning(self, capsys):
        """Stale logs return warning (exit code 1)."""
        from scripts.baremetal.logrotate_status import run

        context = MockContext(
            file_contents={
                "/var/lib/logrotate/status": load_fixture("logrotate_state_stale.txt"),
                "/var/log": "",
                "/var/log/syslog": "log content",
                "/var/log/auth.log": "auth content",
                "/var/log/kern.log": "kern content",
                "/var/log/daemon.log": "daemon content",
            },
        )
        output = Output()

        result = run(["--max-age", "30"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Stale" in captured.out or "stale" in captured.out

    def test_large_log_warning(self, capsys):
        """Large log files return warning (exit code 1)."""
        from scripts.baremetal.logrotate_status import run

        # Create a log file larger than 1MB
        large_content = "x" * (2 * 1024 * 1024)  # 2MB

        context = MockContext(
            file_contents={
                "/var/lib/logrotate/status": load_fixture("logrotate_state_healthy.txt"),
                "/var/log": "",
                "/var/log/syslog": large_content,
            },
        )
        output = Output()

        result = run(["--max-size", "1"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Large log" in captured.out or "large" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.logrotate_status import run

        context = MockContext(
            file_contents={
                "/var/lib/logrotate/status": load_fixture("logrotate_state_healthy.txt"),
                "/var/log": "",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "state_file_found" in data
        assert "tracked_logs" in data
        assert "large_logs" in data
        assert "stale_logs" in data
        assert "status" in data

    def test_warn_only_no_output_when_healthy(self, capsys):
        """With --warn-only, no output when healthy."""
        from scripts.baremetal.logrotate_status import run

        context = MockContext(
            file_contents={
                "/var/lib/logrotate/status": load_fixture("logrotate_state_healthy.txt"),
                "/var/log": "",
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_missing_state_file(self, capsys):
        """Missing state file is reported as info."""
        from scripts.baremetal.logrotate_status import run

        context = MockContext(
            file_contents={
                "/var/log": "",
            },
        )
        output = Output()

        result = run([], output, context)

        # Should still succeed but note missing state file
        assert result == 0
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_invalid_max_size(self, capsys):
        """Invalid --max-size returns exit code 2."""
        from scripts.baremetal.logrotate_status import run

        context = MockContext(
            file_contents={
                "/var/log": "",
            },
        )
        output = Output()

        result = run(["--max-size", "-5"], output, context)

        assert result == 2
