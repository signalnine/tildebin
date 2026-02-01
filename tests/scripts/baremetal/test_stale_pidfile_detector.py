"""Tests for stale_pidfile_detector script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext, load_fixture


class TestStalePidfileDetector:
    """Tests for stale_pidfile_detector."""

    def test_no_pidfiles(self, capsys):
        """No PID files found returns exit code 0."""
        from scripts.baremetal.stale_pidfile_detector import run

        context = MockContext(
            file_contents={
                "/var/run": "",  # Directory exists but no PID files
            },
        )
        # Override glob to return empty
        context.glob = lambda pattern, root=".": []

        output = Output()
        result = run(["-d", "/var/run"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "No PID files" in captured.out or "OK" in captured.out

    def test_valid_pidfiles(self, capsys):
        """Valid PID files return exit code 0."""
        from scripts.baremetal.stale_pidfile_detector import run

        context = MockContext(
            file_contents={
                "/var/run": "",
                "/var/run/nginx.pid": load_fixture("pidfiles", "nginx.pid"),
                "/proc/1234/comm": "nginx\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/var/run/nginx.pid"] if "*.pid" in pattern else []

        output = Output()
        result = run(["-d", "/var/run"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "stale" not in captured.out.lower() or "No stale" in captured.out

    def test_stale_pidfile_detected(self, capsys):
        """Stale PID file (process doesn't exist) returns exit code 1."""
        from scripts.baremetal.stale_pidfile_detector import run

        context = MockContext(
            file_contents={
                "/var/run": "",
                "/var/run/stale.pid": load_fixture("pidfiles", "stale.pid"),
                # No /proc/99999/comm - process doesn't exist
            },
        )
        context.glob = lambda pattern, root=".": ["/var/run/stale.pid"] if "*.pid" in pattern else []

        output = Output()
        result = run(["-d", "/var/run"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "STALE" in captured.out or "stale" in captured.out.lower()

    def test_invalid_pidfile(self, capsys):
        """Invalid PID file content is handled gracefully."""
        from scripts.baremetal.stale_pidfile_detector import run

        context = MockContext(
            file_contents={
                "/var/run": "",
                "/var/run/invalid.pid": load_fixture("pidfiles", "invalid.pid"),
            },
        )
        context.glob = lambda pattern, root=".": ["/var/run/invalid.pid"] if "*.pid" in pattern else []

        output = Output()
        result = run(["-d", "/var/run", "--verbose"], output, context)

        # Invalid files are not stale, so exit code should be 0
        assert result == 0
        captured = capsys.readouterr()
        assert "invalid" in captured.out.lower() or "parse" in captured.out.lower()

    def test_name_mismatch_detection(self, capsys):
        """Process name mismatch is detected with --check-name."""
        from scripts.baremetal.stale_pidfile_detector import run

        context = MockContext(
            file_contents={
                "/var/run": "",
                "/var/run/nginx.pid": load_fixture("pidfiles", "nginx.pid"),
                "/proc/1234/comm": "apache2\n",  # Wrong process name!
            },
        )
        context.glob = lambda pattern, root=".": ["/var/run/nginx.pid"] if "*.pid" in pattern else []

        output = Output()
        result = run(["-d", "/var/run", "--check-name"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "mismatch" in captured.out.lower() or "WARN" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.stale_pidfile_detector import run

        context = MockContext(
            file_contents={
                "/var/run": "",
                "/var/run/nginx.pid": load_fixture("pidfiles", "nginx.pid"),
                "/proc/1234/comm": "nginx\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/var/run/nginx.pid"] if "*.pid" in pattern else []

        output = Output()
        result = run(["-d", "/var/run", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "pidfiles" in data
        assert "summary" in data
        assert "has_issues" in data
        assert "total" in data["summary"]
        assert "stale" in data["summary"]

    def test_multiline_pidfile(self, capsys):
        """Multiline PID file (first line is PID) is handled correctly."""
        from scripts.baremetal.stale_pidfile_detector import run

        context = MockContext(
            file_contents={
                "/var/run": "",
                "/var/run/multi.pid": load_fixture("pidfiles", "multiline.pid"),
                "/proc/1234/comm": "myservice\n",
            },
        )
        context.glob = lambda pattern, root=".": ["/var/run/multi.pid"] if "*.pid" in pattern else []

        output = Output()
        result = run(["-d", "/var/run", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should parse PID 1234 from first line
        assert data["summary"]["valid"] == 1
        assert data["summary"]["stale"] == 0
