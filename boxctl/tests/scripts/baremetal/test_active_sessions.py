"""Tests for active_sessions script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext, load_fixture


class TestActiveSessions:
    """Tests for active_sessions monitoring."""

    def test_healthy_sessions(self, capsys):
        """Normal sessions return exit code 0."""
        from scripts.baremetal.active_sessions import run

        context = MockContext(
            tools_available=["w", "hostname"],
            command_outputs={
                ("w", "-h"): load_fixture("sessions", "w_healthy.txt"),
                ("hostname",): "testhost",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Active Sessions" in captured.out

    def test_root_session_warning(self, capsys):
        """Root sessions with --warn-root flag return exit code 1."""
        from scripts.baremetal.active_sessions import run

        context = MockContext(
            tools_available=["who", "hostname"],
            command_outputs={
                ("who",): load_fixture("sessions", "who_root_session.txt"),
                ("hostname",): "testhost",
            },
        )
        output = Output()

        result = run(["--warn-root"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "root" in captured.out.lower()

    def test_idle_session_warning(self, capsys):
        """Idle sessions exceeding threshold return exit code 1."""
        from scripts.baremetal.active_sessions import run

        context = MockContext(
            tools_available=["w", "hostname"],
            command_outputs={
                ("w", "-h"): load_fixture("sessions", "w_idle_sessions.txt"),
                ("hostname",): "testhost",
            },
        )
        output = Output()

        # Set low max-idle threshold (60 seconds)
        result = run(["--max-idle", "60"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "idle" in captured.out.lower()

    def test_no_sessions(self, capsys):
        """No active sessions return exit code 0."""
        from scripts.baremetal.active_sessions import run

        context = MockContext(
            tools_available=["who", "hostname"],
            command_outputs={
                ("who",): "",
                ("hostname",): "testhost",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "0" in captured.out

    def test_max_sessions_exceeded(self, capsys):
        """Exceeding max sessions returns exit code 1."""
        from scripts.baremetal.active_sessions import run

        context = MockContext(
            tools_available=["who", "hostname"],
            command_outputs={
                ("who",): load_fixture("sessions", "who_many_sessions.txt"),
                ("hostname",): "testhost",
            },
        )
        output = Output()

        result = run(["--max-sessions", "3"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "threshold" in captured.out.lower() or "exceed" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.active_sessions import run

        context = MockContext(
            tools_available=["w", "hostname"],
            command_outputs={
                ("w", "-h"): load_fixture("sessions", "w_healthy.txt"),
                ("hostname",): "testhost",
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "hostname" in data
        assert "session_count" in data
        assert "sessions" in data
        assert "issues" in data
        assert "healthy" in data

    def test_missing_tools_exit_2(self, capsys):
        """Missing both 'w' and 'who' tools returns exit code 2."""
        from scripts.baremetal.active_sessions import run

        context = MockContext(
            tools_available=[],
            command_outputs={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert output.errors
