"""Tests for oom_kill_history script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestOomKillHistory:
    """Tests for oom_kill_history."""

    def test_no_oom_kills_returns_0(self, capsys):
        """No OOM kills returns exit code 0."""
        from scripts.baremetal.oom_kill_history import run

        context = MockContext(
            file_contents={
                "/var/log/dmesg": load_fixture("dmesg_no_oom.txt"),
            },
        )
        output = Output()

        result = run(["--log-file", "/var/log/dmesg"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No OOM kill events found" in captured.out

    def test_oom_kills_returns_1(self, capsys):
        """OOM kills detected returns exit code 1."""
        from scripts.baremetal.oom_kill_history import run

        context = MockContext(
            file_contents={
                "/var/log/dmesg": load_fixture("dmesg_oom_kills.txt"),
            },
        )
        output = Output()

        result = run(["--log-file", "/var/log/dmesg"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "Total OOM kills found" in captured.out

    def test_parses_multiple_oom_events(self, capsys):
        """Parses multiple OOM kill events correctly."""
        from scripts.baremetal.oom_kill_history import run

        context = MockContext(
            file_contents={
                "/var/log/dmesg": load_fixture("dmesg_oom_kills.txt"),
            },
        )
        output = Output()

        result = run(["--log-file", "/var/log/dmesg", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should have found 5 OOM events
        assert data["analysis"]["total_events"] == 5
        # Should have unique processes
        assert data["analysis"]["unique_processes"] == 3  # python3, java, nginx

    def test_json_output_format(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.oom_kill_history import run

        context = MockContext(
            file_contents={
                "/var/log/dmesg": load_fixture("dmesg_oom_kills.txt"),
            },
        )
        output = Output()

        result = run(["--log-file", "/var/log/dmesg", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "analysis" in data
        assert "events" in data
        assert "total_events" in data["analysis"]
        assert "unique_processes" in data["analysis"]
        assert "process_frequency" in data["analysis"]

    def test_detects_cgroup_context(self, capsys):
        """Detects cgroup/container context in OOM kills."""
        from scripts.baremetal.oom_kill_history import run

        context = MockContext(
            file_contents={
                "/var/log/dmesg": load_fixture("dmesg_oom_with_cgroup.txt"),
            },
        )
        output = Output()

        result = run(["--log-file", "/var/log/dmesg", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should detect cgroup distribution
        assert "cgroup_distribution" in data["analysis"]
        cgroups = data["analysis"]["cgroup_distribution"]
        assert cgroups.get("containers", 0) >= 1  # docker container
        assert cgroups.get("kubernetes_pods", 0) >= 1  # kubepods

    def test_warn_only_suppresses_output_when_no_oom(self, capsys):
        """--warn-only suppresses output when no OOM kills found."""
        from scripts.baremetal.oom_kill_history import run

        context = MockContext(
            file_contents={
                "/var/log/dmesg": load_fixture("dmesg_no_oom.txt"),
            },
        )
        output = Output()

        result = run(["--log-file", "/var/log/dmesg", "--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should have minimal or no output
        assert captured.out.strip() == "" or len(captured.out) < 50

    def test_missing_log_file_returns_2(self, capsys):
        """Missing log file returns exit code 2."""
        from scripts.baremetal.oom_kill_history import run

        context = MockContext(
            file_contents={},  # No files
        )
        output = Output()

        result = run(["--log-file", "/nonexistent/file"], output, context)

        assert result == 2
