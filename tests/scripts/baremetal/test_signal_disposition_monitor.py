"""Tests for signal_disposition_monitor script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestSignalDispositionMonitor:
    """Tests for signal_disposition_monitor."""

    def test_no_issues_returns_zero(self, capsys):
        """Normal processes return exit code 0."""
        from scripts.baremetal.signal_disposition_monitor import run

        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
State:\tS (sleeping)
Pid:\t1234
PPid:\t1000
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000000000
SigIgn:\t0000000000000000
SigCgt:\t0000000180004002
""",
                "/proc/1234/cmdline": "python3\x00script.py\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No processes" in captured.out or result == 0

    def test_sigterm_ignored_returns_one(self, capsys):
        """Process ignoring SIGTERM returns exit code 1."""
        from scripts.baremetal.signal_disposition_monitor import run

        # SIGTERM is signal 15, bit 14 in mask = 0x4000
        context = MockContext(
            file_contents={
                "/proc/2000/status": """Name:\tstubborn_daemon
State:\tS (sleeping)
Pid:\t2000
PPid:\t1
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000000000
SigIgn:\t0000000000004000
SigCgt:\t0000000180000002
""",
                "/proc/2000/cmdline": "stubborn_daemon\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/2000"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 1
        assert output.data["total_concerning"] == 1
        assert output.data["high_severity_count"] == 1

    def test_sigterm_blocked_returns_one(self, capsys):
        """Process blocking SIGTERM returns exit code 1."""
        from scripts.baremetal.signal_disposition_monitor import run

        # SIGTERM blocked = 0x4000
        context = MockContext(
            file_contents={
                "/proc/3000/status": """Name:\tblocking_app
State:\tR (running)
Pid:\t3000
PPid:\t1000
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000004000
SigIgn:\t0000000000000000
SigCgt:\t0000000180004002
""",
                "/proc/3000/cmdline": "blocking_app\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/3000"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "SIGTERM" in captured.out or "block" in captured.out.lower()

    def test_systemd_is_whitelisted(self, capsys):
        """Systemd ignoring signals is not flagged."""
        from scripts.baremetal.signal_disposition_monitor import run

        # Systemd is in the expected ignorers list
        context = MockContext(
            file_contents={
                "/proc/1/status": """Name:\tsystemd
State:\tS (sleeping)
Pid:\t1
PPid:\t0
Uid:\t0\t0\t0\t0
SigBlk:\t0000000000000000
SigIgn:\t0000000000004003
SigCgt:\t00000001c1804cef
""",
                "/proc/1/cmdline": "/usr/lib/systemd/systemd\x00",
            }
        )
        context.glob = lambda pattern, root="/": ["/proc/1"] if root == "/proc" else []

        output = Output()
        result = run([], output, context)

        # Systemd is whitelisted, so no issues
        assert result == 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.signal_disposition_monitor import run

        # SIGTERM ignored = 0x4000
        context = MockContext(
            file_contents={
                "/proc/2000/status": """Name:\tstubborn_daemon
State:\tS (sleeping)
Pid:\t2000
PPid:\t1
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000000000
SigIgn:\t0000000000004000
SigCgt:\t0000000180000002
""",
                "/proc/2000/cmdline": "stubborn_daemon\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/2000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_concerning" in data
        assert "high_severity_count" in data
        assert "processes" in data
        assert data["total_concerning"] == 1

    def test_warn_only_silent_when_no_issues(self, capsys):
        """Warn-only mode produces no output when no issues."""
        from scripts.baremetal.signal_disposition_monitor import run

        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
State:\tS (sleeping)
Pid:\t1234
PPid:\t1000
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000000000
SigIgn:\t0000000000000000
SigCgt:\t0000000180004002
""",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_high_only_filter(self, capsys):
        """High-only flag filters to only high severity."""
        from scripts.baremetal.signal_disposition_monitor import run

        context = MockContext(
            file_contents={
                # High severity - ignoring SIGTERM
                "/proc/2000/status": """Name:\thigh_severity
State:\tS (sleeping)
Pid:\t2000
PPid:\t1
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000000000
SigIgn:\t0000000000004000
SigCgt:\t0000000000000000
""",
                "/proc/2000/cmdline": "high_severity\x00",
                # Medium severity - blocking SIGTERM
                "/proc/3000/status": """Name:\tmedium_severity
State:\tS (sleeping)
Pid:\t3000
PPid:\t1000
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000004000
SigIgn:\t0000000000000000
SigCgt:\t0000000000000000
""",
                "/proc/3000/cmdline": "medium_severity\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/2000", "/proc/3000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--high-only", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should only show high severity
        assert data["total_concerning"] == 1
        assert data["processes"][0]["name"] == "high_severity"

    def test_no_blocked_flag(self, capsys):
        """No-blocked flag skips blocked signal checks."""
        from scripts.baremetal.signal_disposition_monitor import run

        context = MockContext(
            file_contents={
                # Only blocking SIGTERM, not ignoring
                "/proc/3000/status": """Name:\tblocking_only
State:\tS (sleeping)
Pid:\t3000
PPid:\t1000
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000004000
SigIgn:\t0000000000000000
SigCgt:\t0000000000000000
""",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/3000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--no-blocked"], output, context)

        # With --no-blocked, blocking SIGTERM is not checked
        assert result == 0

    def test_conflicting_flags_returns_two(self, capsys):
        """Both --no-blocked and --no-ignored returns exit code 2."""
        from scripts.baremetal.signal_disposition_monitor import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--no-blocked", "--no-ignored"], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format produces formatted output."""
        from scripts.baremetal.signal_disposition_monitor import run

        context = MockContext(
            file_contents={
                "/proc/2000/status": """Name:\tstubborn_daemon
State:\tS (sleeping)
Pid:\t2000
PPid:\t1
Uid:\t1000\t1000\t1000\t1000
SigBlk:\t0000000000000000
SigIgn:\t0000000000004000
SigCgt:\t0000000180000002
""",
                "/proc/2000/cmdline": "stubborn_daemon\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/2000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "+" in captured.out or "-" in captured.out
        assert "Signal Disposition" in captured.out or "PID" in captured.out
