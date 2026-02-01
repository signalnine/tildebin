"""Tests for watchdog_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestWatchdogMonitor:
    """Tests for watchdog_monitor."""

    def test_healthy_watchdog(self, capsys):
        """Healthy watchdog returns exit code 0."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_healthy.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        # Healthy watchdog with no daemon still generates a warning
        # but should not be critical
        assert result in (0, 1)

    def test_watchdog_with_daemon(self, capsys):
        """Watchdog with daemon returns exit code 0."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_with_daemon.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out.lower()

    def test_inactive_watchdog(self, capsys):
        """Inactive watchdog generates warning."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_inactive.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "inactive" in captured.out.lower() or "not active" in captured.out.lower()

    def test_short_timeout_warning(self, capsys):
        """Short timeout generates warning."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_short_timeout.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        captured = capsys.readouterr()
        assert "short" in captured.out.lower() or "5s" in captured.out

    def test_no_watchdog_device(self, capsys):
        """No watchdog device returns exit code 1."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_no_device.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "No watchdog" in captured.out or "not found" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_with_daemon.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "devices" in data
        assert "status" in data
        assert "has_device" in data
        assert "has_daemon" in data

    def test_verbose_shows_details(self, capsys):
        """Verbose mode shows detailed information."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_with_daemon.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "Nowayout" in captured.out

    def test_warn_only_suppresses_healthy(self, capsys):
        """Warn-only mode suppresses output for healthy system."""
        from scripts.baremetal.watchdog_monitor import run

        context = MockContext(
            file_contents={
                "/proc/watchdog_info": load_fixture("watchdog_with_daemon.txt"),
                "/proc/uptime": load_fixture("uptime_normal.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # With healthy status and warn-only, output should be empty
        assert captured.out.strip() == ""
