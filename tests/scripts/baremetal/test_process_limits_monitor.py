"""Tests for process_limits_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestProcessLimitsMonitor:
    """Tests for process_limits_monitor."""

    def _create_process_context(
        self,
        pid: int = 1234,
        limits_content: str | None = None,
        status_content: str | None = None,
        name: str = "nginx",
    ) -> MockContext:
        """Create a mock context with process information."""
        if limits_content is None:
            limits_content = load_fixture("process_limits_healthy.txt")
        if status_content is None:
            status_content = load_fixture("process_status_nginx.txt")

        file_contents = {
            "/proc": "directory-marker",
            "/proc/pids": str(pid),
            f"/proc/{pid}/limits": limits_content,
            f"/proc/{pid}/status": status_content,
            f"/proc/{pid}/comm": name,
            f"/proc/{pid}/cmdline": f"/usr/sbin/{name}\x00-g\x00daemon off;",
        }
        return MockContext(file_contents=file_contents)

    def test_healthy_process(self, capsys):
        """Process within limits returns exit code 0."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context()
        output = Output()

        # With low FD count (50 out of 1024 = 4.9%)
        result = run(["--pid", "1234", "--fd-count", "50"], output, context)

        assert result == 0

    def test_high_fd_usage_warning(self, capsys):
        """Process with high FD usage triggers warning."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context()
        output = Output()

        # 850 out of 1024 = 83% (above 80% warning default)
        result = run(["--pid", "1234", "--fd-count", "850"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_critical_fd_usage(self, capsys):
        """Process with critical FD usage triggers critical alert."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context()
        output = Output()

        # 980 out of 1024 = 95.7% (above 95% critical default)
        result = run(["--pid", "1234", "--fd-count", "980"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_low_fd_limit_warning(self, capsys):
        """Process with low FD limit and moderate usage triggers warning."""
        from scripts.baremetal.process_limits_monitor import run

        # Use the low FD limit fixture (100 max)
        limits_content = load_fixture("process_limits_low_fd.txt")
        context = self._create_process_context(limits_content=limits_content)
        output = Output()

        # 85 out of 100 = 85% (above 80% warning)
        result = run(["--pid", "1234", "--fd-count", "85"], output, context)

        assert result == 1

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context()
        output = Output()

        # 750 out of 1024 = 73%
        # With warn=75, crit=90, should be OK
        result = run(
            ["--pid", "1234", "--fd-count", "750", "--warn", "75", "--crit", "90"],
            output,
            context,
        )
        assert result == 0

        # With warn=70, crit=90, should be WARNING
        output2 = Output()
        result = run(
            ["--pid", "1234", "--fd-count", "750", "--warn", "70", "--crit", "90"],
            output2,
            context,
        )
        assert result == 1

    def test_json_output_format(self, capsys):
        """JSON output contains expected structure."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context()
        output = Output()

        result = run(
            ["--pid", "1234", "--fd-count", "50", "--format", "json"], output, context
        )

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "processes" in data
        assert "total_scanned" in data
        assert "processes_with_issues" in data
        assert "issues_found" in data

    def test_table_output_format(self, capsys):
        """Table output has proper format."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context()
        output = Output()

        result = run(
            ["--pid", "1234", "--fd-count", "50", "--format", "table"], output, context
        )

        captured = capsys.readouterr()
        assert "PID" in captured.out
        assert "Name" in captured.out

    def test_name_filter(self, capsys):
        """Name filter limits processes checked."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context(name="nginx")
        output = Output()

        # Filter by "nginx" should find the process
        result = run(
            ["--pid", "1234", "--fd-count", "50", "--name", "nginx", "--format", "json"],
            output,
            context,
        )
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data["processes"]) == 1

        # Filter by "apache" should not find it
        output2 = Output()
        result = run(
            ["--pid", "1234", "--fd-count", "50", "--name", "apache", "--format", "json"],
            output2,
            context,
        )
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data["processes"]) == 0

    def test_invalid_thresholds(self, capsys):
        """Invalid threshold values return error."""
        from scripts.baremetal.process_limits_monitor import run

        context = self._create_process_context()
        output = Output()

        # crit <= warn should fail
        result = run(["--warn", "90", "--crit", "80"], output, context)
        assert result == 2

        # Negative values should fail
        result = run(["--warn", "-10"], output, context)
        assert result == 2
