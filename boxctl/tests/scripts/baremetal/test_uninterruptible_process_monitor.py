"""Tests for uninterruptible_process_monitor script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestUninterruptibleProcessMonitor:
    """Tests for uninterruptible_process_monitor."""

    def test_no_dstate_returns_zero(self, capsys):
        """No D-state processes returns exit code 0."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        # All processes in normal states (S, R)
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (nginx) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 4 0 100000 0 0\n",
                "/proc/200/stat": "200 (python) R 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 200000 0 0\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No" in captured.out and "D-state" in captured.out

    def test_single_dstate_returns_one(self, capsys):
        """Single D-state process returns exit code 1."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (dd) D 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/wchan": "nfs_wait_on_request\n",
                "/proc/100/cmdline": "dd if=/dev/zero of=/mnt/nfs/file\x00",
                "/proc/1/comm": "systemd\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "D-state" in captured.out or "uninterruptible" in captured.out.lower()

    def test_multiple_dstate_grouped(self, capsys):
        """Multiple D-state processes can be grouped by category."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (nfs_client) D 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/wchan": "nfs_wait_on_request\n",
                "/proc/100/cmdline": "/usr/bin/nfs_client\x00",
                "/proc/1/comm": "systemd\n",
                "/proc/200/stat": "200 (dd) D 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 60000 0 0\n",
                "/proc/200/wchan": "blk_mq_get_tag\n",
                "/proc/200/cmdline": "dd if=/dev/sda\x00",
                "/proc/300/stat": "300 (app) D 1 300 300 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 70000 0 0\n",
                "/proc/300/wchan": "mutex_lock\n",
                "/proc/300/cmdline": "/opt/app/worker\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200", "/proc/300"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--group"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        # Should show grouped output with categories
        assert "NFS" in captured.out or "DISK" in captured.out or "LOCK" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (dd) D 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/wchan": "io_schedule\n",
                "/proc/100/cmdline": "dd if=/dev/sda of=/dev/null\x00",
                "/proc/1/comm": "systemd\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_dstate" in data
        assert "processes" in data
        assert "by_category" in data
        assert data["total_dstate"] == 1

    def test_min_age_filter(self, capsys):
        """Min-age filter excludes young D-state processes."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (dd) D 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/wchan": "io_schedule\n",
                "/proc/100/cmdline": "dd if=/dev/sda\x00",
                "/proc/1/comm": "systemd\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        # Set min-age very high
        result = run(["--min-age", "999999999"], output, context)

        assert result == 0

    def test_warn_only_silent_when_no_dstate(self, capsys):
        """Warn-only mode produces no output when no D-state."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (nginx) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 4 0 100000 0 0\n",
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
        from scripts.baremetal.uninterruptible_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (dd) D 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/wchan": "blk_mq_get_tag\n",
                "/proc/100/cmdline": "dd if=/dev/sda\x00",
                "/proc/1/comm": "systemd\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "+" in captured.out or "-" in captured.out
        assert "D-state" in captured.out or "PID" in captured.out

    def test_wait_channel_categorization(self, capsys):
        """Wait channels are properly categorized."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        # Test NFS wait channel
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (nfs_proc) D 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/100/wchan": "nfs_wait_on_request\n",
                "/proc/100/cmdline": "nfs_proc\x00",
                "/proc/1/comm": "systemd\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Check that NFS category is used
        assert data["processes"][0]["wait_category"] == "nfs"
        assert "nfs" in data["by_category"]

    def test_invalid_min_age_returns_two(self, capsys):
        """Negative min-age returns exit code 2."""
        from scripts.baremetal.uninterruptible_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--min-age", "-1"], output, context)

        assert result == 2
