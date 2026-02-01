"""Tests for zombie_process_monitor script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestZombieProcessMonitor:
    """Tests for zombie_process_monitor."""

    def test_no_zombies_returns_zero(self, capsys):
        """No zombie processes returns exit code 0."""
        from scripts.baremetal.zombie_process_monitor import run

        # Mock /proc with no zombie processes
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/200/stat": "200 (nginx) R 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 2000 0 0\n",
            }
        )
        # Override glob to return our mocked PIDs
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No zombie" in captured.out or "0" in str(result)

    def test_single_zombie_returns_one(self, capsys):
        """Single zombie process returns exit code 1."""
        from scripts.baremetal.zombie_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/100/comm": "bash\n",
                "/proc/500/stat": "500 (defunct_child) Z 100 500 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/500"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "zombie" in captured.out.lower() or "1" in captured.out

    def test_multiple_zombies_grouped(self, capsys):
        """Multiple zombies can be grouped by parent."""
        from scripts.baremetal.zombie_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/100/comm": "bash\n",
                "/proc/200/stat": "200 (python) R 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 2000 0 0\n",
                "/proc/200/comm": "python\n",
                "/proc/500/stat": "500 (child1) Z 100 500 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
                "/proc/501/stat": "501 (child2) Z 100 501 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 51000 0 0\n",
                "/proc/600/stat": "600 (worker) Z 200 600 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 52000 0 0\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/200", "/proc/500", "/proc/501", "/proc/600"]
            if root == "/proc"
            else []
        )

        output = Output()
        result = run(["--group"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        # Should show grouped output with parent info
        assert "Parent" in captured.out or "bash" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.zombie_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/100/comm": "bash\n",
                "/proc/500/stat": "500 (defunct) Z 100 500 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/500"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_zombies" in data
        assert "zombies" in data
        assert "by_parent" in data
        assert data["total_zombies"] == 1

    def test_min_age_filter(self, capsys):
        """Min-age filter excludes young zombies."""
        from scripts.baremetal.zombie_process_monitor import run

        # Use btime that makes the zombie young (recent starttime)
        # btime=1704067200, starttime=50000 ticks, with 100 Hz = 500 seconds after boot
        # Current time would need to be close to start for young zombie
        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/100/comm": "bash\n",
                "/proc/500/stat": "500 (young_zombie) Z 100 500 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/500"] if root == "/proc" else []
        )

        output = Output()
        # Set min-age very high so zombie is filtered out
        result = run(["--min-age", "999999999"], output, context)

        assert result == 0

    def test_warn_only_silent_when_no_zombies(self, capsys):
        """Warn-only mode produces no output when no zombies."""
        from scripts.baremetal.zombie_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should be silent
        assert captured.out == ""

    def test_table_format(self, capsys):
        """Table format produces formatted output."""
        from scripts.baremetal.zombie_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
                "/proc/100/stat": "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n",
                "/proc/100/comm": "bash\n",
                "/proc/500/stat": "500 (defunct) Z 100 500 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000 0 0\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/100", "/proc/500"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        # Table format uses box drawing characters or dashes
        assert "+" in captured.out or "-" in captured.out
        assert "zombie" in captured.out.lower() or "PID" in captured.out

    def test_invalid_min_age_returns_two(self, capsys):
        """Negative min-age returns exit code 2."""
        from scripts.baremetal.zombie_process_monitor import run

        context = MockContext(
            file_contents={
                "/proc/stat": "cpu  100 100 100 100\nbtime 1704067200\n",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--min-age", "-1"], output, context)

        assert result == 2
