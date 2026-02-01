"""Tests for process_memory_growth script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestProcessMemoryGrowth:
    """Tests for process_memory_growth."""

    def test_snapshot_mode_returns_zero(self, capsys):
        """Snapshot mode shows current memory and returns 0."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
Uid:\t1000\t1000\t1000\t1000
VmPeak:\t  131072 kB
VmSize:\t  131072 kB
VmRSS:\t   65536 kB
""",
                "/proc/1234/comm": "python3\n",
                "/proc/1234/cmdline": "python3\x00script.py\x00",
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
        from scripts.baremetal.process_memory_growth import run

        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
Uid:\t1000\t1000\t1000\t1000
VmRSS:\t   65536 kB
""",
                "/proc/1234/comm": "python3\n",
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
        assert "top_by_memory" in data
        assert data["snapshot_mode"] is True

    def test_invalid_samples_returns_two(self, capsys):
        """Invalid samples value returns exit code 2."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--samples", "1"], output, context)

        assert result == 2

    def test_invalid_interval_returns_two(self, capsys):
        """Invalid interval returns exit code 2."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--interval", "0", "--snapshot"], output, context)

        assert result == 2

    def test_invalid_min_growth_returns_two(self, capsys):
        """Invalid --min-growth value returns exit code 2."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--min-growth", "-1", "--snapshot"], output, context)

        assert result == 2

    def test_no_processes_returns_two(self, capsys):
        """No readable processes returns exit code 2."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext(file_contents={})
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--snapshot"], output, context)

        assert result == 2

    def test_table_format_snapshot(self, capsys):
        """Table format in snapshot mode produces formatted output."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
Uid:\t1000\t1000\t1000\t1000
VmRSS:\t   65536 kB
""",
                "/proc/1234/comm": "python3\n",
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

    def test_format_size(self, capsys):
        """Size formatting works correctly."""
        from scripts.baremetal.process_memory_growth import format_size

        assert "KB" in format_size(512)
        assert "MB" in format_size(2048)
        assert "GB" in format_size(2 * 1024 * 1024)

    def test_analyze_growth_identifies_critical(self, capsys):
        """Growth analysis correctly identifies critical processes."""
        from scripts.baremetal.process_memory_growth import analyze_growth

        results = [
            {
                "pid": 1000,
                "comm": "growing_app",
                "growth_kb": 10240,  # 10MB
                "growth_pct": 60,  # 60% growth - critical
            },
            {
                "pid": 2000,
                "comm": "warning_app",
                "growth_kb": 5120,  # 5MB
                "growth_pct": 20,  # 20% growth - warning
            },
            {
                "pid": 3000,
                "comm": "stable_app",
                "growth_kb": 100,  # 100KB - below threshold
                "growth_pct": 5,  # 5% - below threshold
            },
        ]

        warnings, critical = analyze_growth(results, min_growth_kb=512, min_growth_pct=10.0)

        assert len(critical) == 1
        assert critical[0]["comm"] == "growing_app"
        assert len(warnings) == 1
        assert warnings[0]["comm"] == "warning_app"

    def test_calculate_growth(self, capsys):
        """Growth calculation works correctly."""
        from scripts.baremetal.process_memory_growth import calculate_growth

        samples = [
            {
                1234: {
                    "pid": 1234,
                    "comm": "test",
                    "cmdline": "test",
                    "user": "testuser",
                    "rss_kb": 10000,
                    "vsize_kb": 50000,
                }
            },
            {
                1234: {
                    "pid": 1234,
                    "comm": "test",
                    "cmdline": "test",
                    "user": "testuser",
                    "rss_kb": 15000,  # Grew by 5000KB
                    "vsize_kb": 55000,
                }
            },
        ]

        results = calculate_growth(samples, interval=5.0)

        assert len(results) == 1
        assert results[0]["growth_kb"] == 5000
        assert results[0]["growth_pct"] == 50.0

    def test_invalid_cmd_pattern_returns_two(self, capsys):
        """Invalid regex pattern returns exit code 2."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--cmd", "[invalid", "--snapshot"], output, context)

        assert result == 2

    def test_user_filter(self, capsys):
        """User filter filters by process owner."""
        from scripts.baremetal.process_memory_growth import run

        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
Uid:\t1000\t1000\t1000\t1000
VmRSS:\t   65536 kB
""",
                "/proc/1234/comm": "python3\n",
                "/proc/2000/status": """Name:\tnginx
Uid:\t33\t33\t33\t33
VmRSS:\t   32768 kB
""",
                "/proc/2000/comm": "nginx\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234", "/proc/2000"] if root == "/proc" else []
        )

        output = Output()
        # Filter to non-existent user should return no processes
        result = run(["--snapshot", "--user", "nobody", "--format", "json"], output, context)

        # Since no processes match, it returns error
        assert result == 2
