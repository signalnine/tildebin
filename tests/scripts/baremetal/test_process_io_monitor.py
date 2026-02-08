"""Tests for process_io_monitor script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestProcessIOMonitor:
    """Tests for process_io_monitor."""

    def test_snapshot_mode_returns_zero(self, capsys):
        """Snapshot mode shows cumulative I/O and returns 0."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext(
            file_contents={
                "/proc/1234/io": """rchar: 5242880
wchar: 1048576
syscr: 1000
syscw: 500
read_bytes: 2097152
write_bytes: 524288
cancelled_write_bytes: 0
""",
                "/proc/1234/comm": "python3\n",
                "/proc/1234/cmdline": "python3\x00script.py\x00",
                "/proc/1234/status": "Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--snapshot"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "python3" in captured.out

    def test_snapshot_json_output(self, capsys):
        """Snapshot mode JSON output contains expected fields."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext(
            file_contents={
                "/proc/1234/io": """rchar: 5242880
wchar: 1048576
syscr: 1000
syscw: 500
read_bytes: 2097152
write_bytes: 524288
cancelled_write_bytes: 0
""",
                "/proc/1234/comm": "python3\n",
                "/proc/1234/cmdline": "python3\x00",
                "/proc/1234/status": "Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--snapshot", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "top_consumers" in data
        assert data["snapshot_mode"] is True
        assert data["summary"]["total_processes_sampled"] == 1

    def test_invalid_interval_returns_two(self, capsys):
        """Invalid interval returns exit code 2."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--interval", "0"], output, context)

        assert result == 2

    def test_invalid_top_returns_two(self, capsys):
        """Invalid --top value returns exit code 2."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--top", "0", "--snapshot"], output, context)

        assert result == 2

    def test_invalid_threshold_returns_two(self, capsys):
        """Invalid threshold value returns exit code 2."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--warn-threshold", "abc", "--snapshot"], output, context)

        assert result == 2

    def test_no_processes_returns_two(self, capsys):
        """No readable processes returns exit code 2."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext(file_contents={})
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--snapshot"], output, context)

        assert result == 2

    def test_table_format_snapshot(self, capsys):
        """Table format in snapshot mode produces formatted output."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext(
            file_contents={
                "/proc/1234/io": """rchar: 5242880
wchar: 1048576
syscr: 1000
syscw: 500
read_bytes: 2097152
write_bytes: 524288
cancelled_write_bytes: 0
""",
                "/proc/1234/comm": "python3\n",
                "/proc/1234/cmdline": "python3\x00",
                "/proc/1234/status": "Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--snapshot", "--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "PID" in captured.out
        assert "Command" in captured.out
        assert "-" in captured.out

    def test_threshold_parsing_with_suffix(self, capsys):
        """Threshold values with K/M/G suffix are parsed correctly."""
        from scripts.baremetal.process_io_monitor import parse_threshold

        assert parse_threshold("10K") == 10 * 1024
        assert parse_threshold("10M") == 10 * 1024 * 1024
        assert parse_threshold("1G") == 1024 * 1024 * 1024
        assert parse_threshold("100") == 100

    def test_format_bytes(self, capsys):
        """Bytes formatting works correctly."""
        from scripts.baremetal.process_io_monitor import format_bytes

        assert "B" in format_bytes(100)
        assert "KB" in format_bytes(2048)
        assert "MB" in format_bytes(2 * 1024 * 1024)
        assert "GB" in format_bytes(2 * 1024 * 1024 * 1024)

    def test_verbose_output(self, capsys):
        """Verbose output includes syscall counts."""
        from scripts.baremetal.process_io_monitor import run

        context = MockContext(
            file_contents={
                "/proc/1234/io": """rchar: 5242880
wchar: 1048576
syscr: 1000
syscw: 500
read_bytes: 2097152
write_bytes: 524288
cancelled_write_bytes: 0
""",
                "/proc/1234/comm": "python3\n",
                "/proc/1234/cmdline": "python3\x00",
                "/proc/1234/status": "Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--snapshot", "--verbose"], output, context)

        assert output.data["top_consumers"][0]["syscr"] == 1000
        assert output.data["top_consumers"][0]["syscw"] == 500

    def test_io_stats_parsed_correctly(self, capsys):
        """I/O stats are parsed correctly from /proc/[pid]/io."""
        from scripts.baremetal.process_io_monitor import parse_proc_io

        content = """rchar: 5242880
wchar: 1048576
syscr: 1000
syscw: 500
read_bytes: 2097152
write_bytes: 524288
cancelled_write_bytes: 0
"""
        result = parse_proc_io(content)

        assert result["rchar"] == 5242880
        assert result["wchar"] == 1048576
        assert result["syscr"] == 1000
        assert result["syscw"] == 500
        assert result["read_bytes"] == 2097152
        assert result["write_bytes"] == 524288
