"""Tests for oom_risk_analyzer script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestOomRiskAnalyzer:
    """Tests for oom_risk_analyzer."""

    def test_healthy_processes_returns_0(self, capsys):
        """Healthy processes (low OOM scores) return exit code 0."""
        from scripts.baremetal.oom_risk_analyzer import run

        # Process 1 has score 0, process 1000 has score 150 - both below warn threshold
        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/1/oom_score": load_fixture("oom/proc_1_oom_score"),
                "/proc/1/oom_score_adj": load_fixture("oom/proc_1_oom_score_adj"),
                "/proc/1/status": load_fixture("oom/proc_1_status"),
                "/proc/1/cmdline": load_fixture("oom/proc_1_cmdline"),
                "/proc/1000/oom_score": load_fixture("oom/proc_1000_oom_score"),
                "/proc/1000/oom_score_adj": load_fixture("oom/proc_1000_oom_score_adj"),
                "/proc/1000/status": load_fixture("oom/proc_1000_status"),
                "/proc/1000/cmdline": load_fixture("oom/proc_1000_cmdline"),
            },
        )
        output = Output()

        result = run(["--pids", "1", "1000", "--proc-root", "/proc"], output, context)

        assert result == 0

    def test_warning_process_returns_1(self, capsys):
        """Process with warning-level OOM score returns exit code 1."""
        from scripts.baremetal.oom_risk_analyzer import run

        # Process 2000 has score 650, above warn threshold 500
        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/2000/oom_score": load_fixture("oom/proc_2000_oom_score"),
                "/proc/2000/oom_score_adj": load_fixture("oom/proc_2000_oom_score_adj"),
                "/proc/2000/status": load_fixture("oom/proc_2000_status"),
                "/proc/2000/cmdline": load_fixture("oom/proc_2000_cmdline"),
            },
        )
        output = Output()

        result = run(["--pids", "2000", "--proc-root", "/proc"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_critical_process_returns_1(self, capsys):
        """Process with critical-level OOM score returns exit code 1."""
        from scripts.baremetal.oom_risk_analyzer import run

        # Process 3000 has score 900, above crit threshold 800
        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/3000/oom_score": load_fixture("oom/proc_3000_oom_score"),
                "/proc/3000/oom_score_adj": load_fixture("oom/proc_3000_oom_score_adj"),
                "/proc/3000/status": load_fixture("oom/proc_3000_status"),
                "/proc/3000/cmdline": load_fixture("oom/proc_3000_cmdline"),
            },
        )
        output = Output()

        result = run(["--pids", "3000", "--proc-root", "/proc"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_json_output_format(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.oom_risk_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/1000/oom_score": load_fixture("oom/proc_1000_oom_score"),
                "/proc/1000/oom_score_adj": load_fixture("oom/proc_1000_oom_score_adj"),
                "/proc/1000/status": load_fixture("oom/proc_1000_status"),
                "/proc/1000/cmdline": load_fixture("oom/proc_1000_cmdline"),
            },
        )
        output = Output()

        result = run(["--pids", "1000", "--proc-root", "/proc", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "system" in data
        assert "thresholds" in data
        assert "top_processes" in data
        assert "issues" in data
        assert "mem_total_kb" in data["system"]

    def test_custom_thresholds(self, capsys):
        """Custom thresholds are respected."""
        from scripts.baremetal.oom_risk_analyzer import run

        # Process 2000 has score 650
        # With warn=700, crit=900, should be OK
        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
                "/proc/2000/oom_score": load_fixture("oom/proc_2000_oom_score"),
                "/proc/2000/oom_score_adj": load_fixture("oom/proc_2000_oom_score_adj"),
                "/proc/2000/status": load_fixture("oom/proc_2000_status"),
                "/proc/2000/cmdline": load_fixture("oom/proc_2000_cmdline"),
            },
        )
        output = Output()

        result = run(["--pids", "2000", "--proc-root", "/proc", "--warn", "700", "--crit", "900"], output, context)

        assert result == 0

    def test_invalid_thresholds_returns_2(self, capsys):
        """Invalid threshold combinations return exit code 2."""
        from scripts.baremetal.oom_risk_analyzer import run

        context = MockContext(
            file_contents={
                "/proc/meminfo": load_fixture("meminfo_healthy.txt"),
            },
        )
        output = Output()

        # warn >= crit should fail
        result = run(["--warn", "800", "--crit", "500"], output, context)

        assert result == 2

    def test_missing_meminfo_returns_2(self, capsys):
        """Missing /proc/meminfo returns exit code 2."""
        from scripts.baremetal.oom_risk_analyzer import run

        context = MockContext(
            file_contents={},  # No files
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
