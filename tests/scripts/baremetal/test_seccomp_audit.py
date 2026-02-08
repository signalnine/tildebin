"""Tests for seccomp_audit script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestSeccompAudit:
    """Tests for seccomp_audit."""

    def test_no_proc(self, capsys):
        """/proc doesn't exist returns exit code 2."""
        from scripts.baremetal.seccomp_audit import run

        context = MockContext(file_contents={})
        output = Output()
        result = run([], output, context)

        assert result == 2
        assert output.errors

    def test_all_filtered(self, capsys):
        """All processes with seccomp filtering returns exit code 0."""
        from scripts.baremetal.seccomp_audit import run

        context = MockContext(
            file_contents={
                "/proc": "",  # /proc exists
                "/proc/1/status": "Name:\tsystemd\nSeccomp:\t2\nSeccomp_filters:\t1\n",
                "/proc/1/comm": "systemd",
                "/proc/200/status": "Name:\tsshd\nSeccomp:\t2\nSeccomp_filters:\t3\n",
                "/proc/200/comm": "sshd",
                "/proc/300/status": "Name:\tcontainerd\nSeccomp:\t2\nSeccomp_filters:\t2\n",
                "/proc/300/comm": "containerd",
            }
        )

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Unfiltered (mode 0): 0" in captured.out

    def test_mixed_filtering(self, capsys):
        """Mix of filtered and unfiltered processes returns exit code 0."""
        from scripts.baremetal.seccomp_audit import run

        context = MockContext(
            file_contents={
                "/proc": "",  # /proc exists
                "/proc/1/status": "Name:\tinit\nSeccomp:\t0\n",
                "/proc/1/comm": "init",
                "/proc/100/status": "Name:\tsshd\nSeccomp:\t2\nSeccomp_filters:\t1\n",
                "/proc/100/comm": "sshd",
                "/proc/200/status": "Name:\tnginx\nSeccomp:\t2\nSeccomp_filters:\t2\n",
                "/proc/200/comm": "nginx",
                "/proc/300/status": "Name:\tbash\nSeccomp:\t0\n",
                "/proc/300/comm": "bash",
            }
        )

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Unfiltered (mode 0): 2" in captured.out
        assert "Filtered (mode 1+2): 2" in captured.out

    def test_process_disappeared(self, capsys):
        """PID dir exists in glob but status read fails is gracefully skipped."""
        from scripts.baremetal.seccomp_audit import run

        context = MockContext(
            file_contents={
                "/proc": "",  # /proc exists
                "/proc/1/status": "Name:\tinit\nSeccomp:\t2\nSeccomp_filters:\t1\n",
                "/proc/1/comm": "init",
                # PID 999 has a comm file so it shows up in glob,
                # but no status file (process disappeared)
                "/proc/999/comm": "gone",
                "/proc/100/status": "Name:\tsshd\nSeccomp:\t2\nSeccomp_filters:\t1\n",
                "/proc/100/comm": "sshd",
            }
        )

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Should only count the 2 processes that had valid status files
        assert "Total processes scanned: 2" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains summary stats and process list."""
        from scripts.baremetal.seccomp_audit import run

        context = MockContext(
            file_contents={
                "/proc": "",  # /proc exists
                "/proc/1/status": "Name:\tinit\nSeccomp:\t0\n",
                "/proc/1/comm": "init",
                "/proc/100/status": "Name:\tsshd\nSeccomp:\t2\nSeccomp_filters:\t1\n",
                "/proc/100/comm": "sshd",
                "/proc/200/status": "Name:\tstrict_app\nSeccomp:\t1\n",
                "/proc/200/comm": "strict_app",
                "/proc/300/status": "Name:\tbash\nSeccomp:\t0\n",
                "/proc/300/comm": "bash",
            }
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "unfiltered_processes" in data
        assert "timestamp" in data

        summary = data["summary"]
        assert summary["total_processes"] == 4
        assert summary["seccomp_disabled"] == 2
        assert summary["seccomp_strict"] == 1
        assert summary["seccomp_filter"] == 1
        assert summary["filtered"] == 2
        assert summary["unfiltered"] == 2

        # Check unfiltered process list
        unfiltered = data["unfiltered_processes"]
        assert len(unfiltered) == 2
        comms = [p["comm"] for p in unfiltered]
        assert "init" in comms
        assert "bash" in comms
