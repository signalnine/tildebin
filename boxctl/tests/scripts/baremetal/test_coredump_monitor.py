"""Tests for coredump_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "log"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestCoredumpMonitor:
    """Tests for coredump_monitor."""

    def test_systemd_coredump_healthy(self, capsys):
        """Systemd-coredump configuration returns exit code 0."""
        from scripts.baremetal.coredump_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/core_pattern": load_fixture("core_pattern_systemd.txt"),
                "/proc/sys/kernel/core_uses_pid": "1\n",
                "/proc/sys/kernel/core_pipe_limit": "16\n",
                "/etc/systemd/coredump.conf": load_fixture("coredump_conf.txt"),
                "/proc/self/limits": load_fixture("proc_self_limits.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "systemd-coredump" in captured.out

    def test_disabled_coredump_warning(self, capsys):
        """Disabled coredump returns warning (exit code 1)."""
        from scripts.baremetal.coredump_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/core_pattern": load_fixture("core_pattern_disabled.txt"),
                "/proc/sys/kernel/core_uses_pid": "0\n",
                "/proc/sys/kernel/core_pipe_limit": "0\n",
                "/proc/self/limits": load_fixture("proc_self_limits.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_file_pattern_healthy(self, capsys):
        """File-based core pattern returns exit code 0."""
        from scripts.baremetal.coredump_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/core_pattern": load_fixture("core_pattern_file.txt"),
                "/proc/sys/kernel/core_uses_pid": "1\n",
                "/proc/sys/kernel/core_pipe_limit": "0\n",
                "/proc/self/limits": load_fixture("proc_self_limits.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Core Pattern" in captured.out

    def test_systemd_storage_none_warning(self, capsys):
        """systemd-coredump with Storage=none returns warning."""
        from scripts.baremetal.coredump_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/core_pattern": load_fixture("core_pattern_systemd.txt"),
                "/proc/sys/kernel/core_uses_pid": "1\n",
                "/proc/sys/kernel/core_pipe_limit": "16\n",
                "/etc/systemd/coredump.conf": load_fixture("coredump_conf_disabled.txt"),
                "/proc/self/limits": load_fixture("proc_self_limits.txt"),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "none" in captured.out or "discarded" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.coredump_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/core_pattern": load_fixture("core_pattern_systemd.txt"),
                "/proc/sys/kernel/core_uses_pid": "1\n",
                "/proc/sys/kernel/core_pipe_limit": "16\n",
                "/etc/systemd/coredump.conf": load_fixture("coredump_conf.txt"),
                "/proc/self/limits": load_fixture("proc_self_limits.txt"),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "core_pattern" in data
        assert "ulimit" in data
        assert "systemd_coredump" in data
        assert "issues" in data
        assert "status" in data

    def test_missing_core_pattern(self, capsys):
        """Missing core_pattern file returns exit code 2."""
        from scripts.baremetal.coredump_monitor import run

        context = MockContext(
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_warn_only_no_output_when_healthy(self, capsys):
        """With --warn-only, no output when healthy."""
        from scripts.baremetal.coredump_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/core_pattern": load_fixture("core_pattern_systemd.txt"),
                "/proc/sys/kernel/core_uses_pid": "1\n",
                "/proc/sys/kernel/core_pipe_limit": "16\n",
                "/etc/systemd/coredump.conf": load_fixture("coredump_conf.txt"),
                "/proc/self/limits": load_fixture("proc_self_limits.txt"),
            },
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""
