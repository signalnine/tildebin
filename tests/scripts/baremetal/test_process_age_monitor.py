"""Tests for process_age_monitor script."""

import json
import pytest
from datetime import datetime, timezone

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestProcessAgeMonitor:
    """Tests for process_age_monitor."""

    def test_no_old_processes_returns_zero(self, capsys):
        """No processes exceeding thresholds returns exit code 0."""
        from scripts.baremetal.process_age_monitor import run

        # btime 1704067200 = 2024-01-01 00:00:00 UTC
        # starttime 100000 ticks = 1000 seconds after boot
        # If we pretend "now" is only 1 day after boot, processes are young
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (nginx) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 4 0 100000 0 0\n",
                "/proc/100/cmdline": "nginx: master process\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t4\nPPid:\t1\nState:\tS\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        # Use very high thresholds so nothing is flagged
        result = run(["--warn-days", "9999", "--crit-days", "99999", "--min-age", "0"], output, context)

        assert result == 0

    def test_old_process_returns_one(self, capsys):
        """Process exceeding warning threshold returns exit code 1."""
        from scripts.baremetal.process_age_monitor import run

        # Process started 100 ticks after boot (1 second after boot)
        # With btime in the past, process will be very old
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1577836800\n",  # 2020-01-01
                "/proc/100/stat": "100 (old_daemon) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n",
                "/proc/100/cmdline": "/usr/bin/old_daemon\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t1\nPPid:\t1\nState:\tS\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        # Low thresholds to catch old processes
        result = run(["--warn-days", "1", "--crit-days", "7", "--min-age", "0"], output, context)

        assert result == 1

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.process_age_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1577836800\n",
                "/proc/100/stat": "100 (myapp) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n",
                "/proc/100/cmdline": "/usr/bin/myapp\x00",
                "/proc/100/status": "Uid:\t1000\nThreads:\t1\nPPid:\t1\nState:\tS\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json", "--min-age", "0"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "status" in data
        assert "summary" in data
        assert "all_processes" in data
        assert "total_processes" in data["summary"]

    def test_user_filter(self, capsys):
        """User filter only shows processes from specified user."""
        from scripts.baremetal.process_age_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (root_app) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100000 0 0\n",
                "/proc/100/cmdline": "/usr/bin/root_app\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t1\nPPid:\t1\nState:\tS\n",
                "/proc/200/stat": "200 (user_app) S 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 200000 0 0\n",
                "/proc/200/cmdline": "/usr/bin/user_app\x00",
                "/proc/200/status": "Uid:\t1000\nThreads:\t1\nPPid:\t1\nState:\tS\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json", "--user", "1000", "--min-age", "0"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should only have the user_app process
        assert len(data["all_processes"]) == 1
        assert data["all_processes"][0]["comm"] == "user_app"

    def test_cmd_filter(self, capsys):
        """Command filter only shows matching processes."""
        from scripts.baremetal.process_age_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (nginx) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100000 0 0\n",
                "/proc/100/cmdline": "nginx: master\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t1\nPPid:\t1\nState:\tS\n",
                "/proc/200/stat": "200 (redis) S 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 200000 0 0\n",
                "/proc/200/cmdline": "redis-server\x00",
                "/proc/200/status": "Uid:\t0\nThreads:\t1\nPPid:\t1\nState:\tS\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json", "--cmd", "nginx", "--min-age", "0"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert len(data["all_processes"]) == 1
        assert data["all_processes"][0]["comm"] == "nginx"

    def test_table_format(self, capsys):
        """Table format produces formatted output."""
        from scripts.baremetal.process_age_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (myapp) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100000 0 0\n",
                "/proc/100/cmdline": "/usr/bin/myapp\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t1\nPPid:\t1\nState:\tS\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "table", "--min-age", "0"], output, context)

        captured = capsys.readouterr()
        assert "PID" in captured.out
        assert "Command" in captured.out
        assert "-" in captured.out

    def test_no_processes_found(self, capsys):
        """No matching processes shows appropriate message."""
        from scripts.baremetal.process_age_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No matching" in captured.out

    def test_invalid_crit_less_than_warn(self, capsys):
        """crit-days less than warn-days returns exit code 2."""
        from scripts.baremetal.process_age_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--warn-days", "30", "--crit-days", "10"], output, context)

        assert result == 2

    def test_invalid_negative_min_age(self, capsys):
        """Negative min-age returns exit code 2."""
        from scripts.baremetal.process_age_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--min-age", "-1"], output, context)

        assert result == 2
