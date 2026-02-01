"""Tests for inotify_exhaustion_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestInotifyExhaustionMonitor:
    """Tests for inotify_exhaustion_monitor."""

    def test_healthy_usage(self, capsys):
        """Healthy inotify usage returns exit code 0."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        # Simulate a process with inotify watches
        context = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": load_fixture("inotify_limits_healthy.txt"),
                "/proc/sys/fs/inotify/max_user_instances": load_fixture("inotify_max_instances.txt"),
                "/proc/sys/fs/inotify/max_queued_events": load_fixture("inotify_max_queued.txt"),
                "/proc/1234/comm": "test_proc\n",
                "/proc/1234/fd/3": "anon_inode:[inotify]\n",
                "/proc/1234/fdinfo/3": "inotify wd:1 ino:1234\ninotify wd:2 ino:5678\n",
            },
        )
        output = Output()

        result = run([], output, context)

        # With 2 watches out of 524288 max, should be healthy
        assert result == 0

    def test_warning_high_usage(self, capsys):
        """Warning when inotify usage is high."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        # Create a process with many watches (simulate 75% usage)
        # Using low limit of 8192, so 6200 watches = ~75%
        watches = "\n".join([f"inotify wd:{i} ino:{i*100}" for i in range(6200)])
        context = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": load_fixture("inotify_limits_low.txt"),  # 8192
                "/proc/sys/fs/inotify/max_user_instances": load_fixture("inotify_max_instances.txt"),
                "/proc/sys/fs/inotify/max_queued_events": load_fixture("inotify_max_queued.txt"),
                "/proc/1234/comm": "heavy_watcher\n",
                "/proc/1234/fd/3": "anon_inode:[inotify]\n",
                "/proc/1234/fdinfo/3": watches,
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "[WARNING]" in captured.out

    def test_low_limit_warning(self, capsys):
        """Warning when max_user_watches limit is too low."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": load_fixture("inotify_limits_low.txt"),  # 8192 < 65536
                "/proc/sys/fs/inotify/max_user_instances": load_fixture("inotify_max_instances.txt"),
                "/proc/sys/fs/inotify/max_queued_events": load_fixture("inotify_max_queued.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "low" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": load_fixture("inotify_limits_healthy.txt"),
                "/proc/sys/fs/inotify/max_user_instances": load_fixture("inotify_max_instances.txt"),
                "/proc/sys/fs/inotify/max_queued_events": load_fixture("inotify_max_queued.txt"),
                "/proc/1234/comm": "test_proc\n",
                "/proc/1234/fd/3": "anon_inode:[inotify]\n",
                "/proc/1234/fdinfo/3": "inotify wd:1 ino:1234\n",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "limits" in data
        assert "summary" in data
        assert "issues" in data
        assert "processes" in data
        assert "healthy" in data
        assert "max_user_watches" in data["limits"]

    def test_warn_only_no_issues(self, capsys):
        """Warn-only mode with healthy system produces minimal output."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": load_fixture("inotify_limits_healthy.txt"),
                "/proc/sys/fs/inotify/max_user_instances": load_fixture("inotify_max_instances.txt"),
                "/proc/sys/fs/inotify/max_queued_events": load_fixture("inotify_max_queued.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0

    def test_invalid_thresholds(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": load_fixture("inotify_limits_healthy.txt"),
            },
        )
        output = Output()

        # Warning >= critical is invalid
        result = run(["--warn", "90", "--crit", "80"], output, context)

        assert result == 2

    def test_missing_inotify_limits(self, capsys):
        """Missing inotify limits returns exit code 2."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        context = MockContext(
            file_contents={},  # No inotify files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.inotify_exhaustion_monitor import run

        # Create 50% usage (4096/8192)
        watches = "\n".join([f"inotify wd:{i} ino:{i*100}" for i in range(4096)])
        context = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": load_fixture("inotify_limits_low.txt"),  # 8192
                "/proc/sys/fs/inotify/max_user_instances": load_fixture("inotify_max_instances.txt"),
                "/proc/sys/fs/inotify/max_queued_events": load_fixture("inotify_max_queued.txt"),
                "/proc/1234/comm": "watcher\n",
                "/proc/1234/fd/3": "anon_inode:[inotify]\n",
                "/proc/1234/fdinfo/3": watches,
            },
        )
        output = Output()

        # With default thresholds (75/90), 50% should be OK (except low limit warning)
        # Let's use high enough limit to avoid low limit warning
        context_high_limit = MockContext(
            file_contents={
                "/proc/sys/fs/inotify/max_user_watches": "200000\n",  # High enough
                "/proc/sys/fs/inotify/max_user_instances": load_fixture("inotify_max_instances.txt"),
                "/proc/sys/fs/inotify/max_queued_events": load_fixture("inotify_max_queued.txt"),
                "/proc/1234/comm": "watcher\n",
                "/proc/1234/fd/3": "anon_inode:[inotify]\n",
                "/proc/1234/fdinfo/3": "\n".join([f"inotify wd:{i} ino:{i*100}" for i in range(100000)]),  # 50%
            },
        )

        # With threshold 40, 50% should trigger warning
        result = run(["--warn", "40", "--crit", "80"], output, context_high_limit)

        assert result == 1
