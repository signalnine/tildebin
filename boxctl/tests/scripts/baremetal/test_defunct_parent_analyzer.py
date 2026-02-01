"""Tests for defunct_parent_analyzer script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestDefunctParentAnalyzer:
    """Tests for defunct_parent_analyzer."""

    def test_no_orphans_returns_zero(self, capsys):
        """No orphaned processes with issues returns exit code 0."""
        from scripts.baremetal.defunct_parent_analyzer import run

        # All processes have proper parents (not ppid=1) or are expected daemons
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 200 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/200/stat": "200 (sshd) S 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0\n",
                "/proc/200/cmdline": "sshd: server\x00",
                "/proc/200/status": "Uid:\t0\nThreads:\t1\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 0

    def test_orphaned_process_returns_one(self, capsys):
        """Orphaned process with issues returns exit code 1."""
        from scripts.baremetal.defunct_parent_analyzer import run

        # Process with ppid=1 that is NOT an expected daemon
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (my_worker) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/cmdline": "/usr/bin/my_worker --daemon\x00",
                "/proc/100/status": "Uid:\t1000\nThreads:\t2\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "orphan" in captured.out.lower() or "ISSUE" in captured.out

    def test_expected_daemon_not_flagged(self, capsys):
        """Expected daemons like sshd, nginx are not flagged as issues."""
        from scripts.baremetal.defunct_parent_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (sshd) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0\n",
                "/proc/100/cmdline": "/usr/sbin/sshd -D\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t1\n",
                "/proc/200/stat": "200 (nginx) S 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/200/cmdline": "nginx: master process\x00",
                "/proc/200/status": "Uid:\t0\nThreads:\t1\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        # No issues because sshd and nginx are expected
        assert result == 0

    def test_all_flag_includes_expected(self, capsys):
        """--all flag includes expected reparented processes."""
        from scripts.baremetal.defunct_parent_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (sshd) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0\n",
                "/proc/100/cmdline": "/usr/sbin/sshd -D\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t1\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--all"], output, context)

        assert result == 1  # Now sshd is included and has issues
        captured = capsys.readouterr()
        assert "sshd" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.defunct_parent_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (orphan_app) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/cmdline": "/opt/app/orphan_app\x00",
                "/proc/100/status": "Uid:\t1000\nThreads:\t1\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "orphans" in data
        assert data["summary"]["total_orphans"] == 1
        assert data["summary"]["with_issues"] == 1

    def test_min_age_filter(self, capsys):
        """Min-age filter excludes young orphans."""
        from scripts.baremetal.defunct_parent_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (young_app) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/cmdline": "/opt/app/young_app\x00",
                "/proc/100/status": "Uid:\t1000\nThreads:\t1\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        # Set min-age very high
        result = run(["--min-age", "999999999"], output, context)

        assert result == 0

    def test_warn_only_silent_when_no_issues(self, capsys):
        """Warn-only mode produces no output when no issues."""
        from scripts.baremetal.defunct_parent_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                # Only expected daemons
                "/proc/100/stat": "100 (sshd) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0\n",
                "/proc/100/cmdline": "/usr/sbin/sshd -D\x00",
                "/proc/100/status": "Uid:\t0\nThreads:\t1\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_table_format(self, capsys):
        """Table format produces formatted output."""
        from scripts.baremetal.defunct_parent_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (orphan_app) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/cmdline": "/opt/app/orphan_app\x00",
                "/proc/100/status": "Uid:\t1000\nThreads:\t1\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "ORPHANED" in captured.out or "=" in captured.out
        assert "PID" in captured.out

    def test_invalid_min_age_returns_two(self, capsys):
        """Negative min-age returns exit code 2."""
        from scripts.baremetal.defunct_parent_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--min-age", "-1"], output, context)

        assert result == 2
