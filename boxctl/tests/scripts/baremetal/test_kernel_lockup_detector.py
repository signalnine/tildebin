"""Tests for kernel_lockup_detector script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "kernel"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestKernelLockupDetector:
    """Tests for kernel_lockup_detector script."""

    def test_clean_dmesg_returns_0(self, capsys):
        """Clean dmesg returns exit code 0."""
        from scripts.baremetal.kernel_lockup_detector import run

        context = MockContext(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_clean.txt"),
                ("ps", "-eo", "pid,stat,wchan:32,comm", "--no-headers"): "1 Ss -  systemd\n2 S kthreadd\n",
            },
            file_contents={
                "/proc/sys/kernel/nmi_watchdog": "1\n",
                "/proc/sys/kernel/watchdog_thresh": "10\n",
                "/proc/sys/kernel/hung_task_timeout_secs": "120\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["summary"]["critical_count"] == 0
        assert output.data["summary"]["warning_count"] == 0

    def test_soft_lockup_detected(self, capsys):
        """Soft lockup is detected as warning."""
        from scripts.baremetal.kernel_lockup_detector import run

        context = MockContext(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_lockups.txt"),
                ("ps", "-eo", "pid,stat,wchan:32,comm", "--no-headers"): "1 Ss - systemd\n",
            },
            file_contents={
                "/proc/sys/kernel/nmi_watchdog": "1\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        # Should detect soft lockup
        issues = output.data["issues"]
        assert any(i["type"] == "soft_lockup" for i in issues)

    def test_rcu_stall_detected(self, capsys):
        """RCU stall is detected."""
        from scripts.baremetal.kernel_lockup_detector import run

        context = MockContext(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_lockups.txt"),
                ("ps", "-eo", "pid,stat,wchan:32,comm", "--no-headers"): "1 Ss - systemd\n",
            },
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        issues = output.data["issues"]
        assert any(i["type"] == "rcu_stall" for i in issues)

    def test_hung_task_detected(self, capsys):
        """Hung task in dmesg is detected."""
        from scripts.baremetal.kernel_lockup_detector import run

        context = MockContext(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_lockups.txt"),
                ("ps", "-eo", "pid,stat,wchan:32,comm", "--no-headers"): "1 Ss - systemd\n",
            },
            file_contents={},
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        issues = output.data["issues"]
        assert any(i["type"] == "hung_task" for i in issues)

    def test_missing_dmesg_returns_2(self, capsys):
        """Missing dmesg returns exit code 2."""
        from scripts.baremetal.kernel_lockup_detector import run

        context = MockContext(
            tools_available=[],  # No dmesg
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.kernel_lockup_detector import run

        context = MockContext(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_clean.txt"),
                ("ps", "-eo", "pid,stat,wchan:32,comm", "--no-headers"): "1 Ss - systemd\n",
            },
            file_contents={},
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "issues" in data
        assert "kernel_config" in data

    def test_d_state_processes_detected(self, capsys):
        """D-state processes are counted."""
        from scripts.baremetal.kernel_lockup_detector import run

        context = MockContext(
            tools_available=["dmesg", "ps"],
            command_outputs={
                ("dmesg", "-T"): load_fixture("dmesg_clean.txt"),
                # Many D-state processes
                ("ps", "-eo", "pid,stat,wchan:32,comm", "--no-headers"): (
                    "1 D wait_for_io kworker\n"
                    "2 D wait_for_io process1\n"
                    "3 D wait_for_io process2\n"
                    "4 D wait_for_io process3\n"
                    "5 D wait_for_io process4\n"
                    "6 D wait_for_io process5\n"
                ),
            },
            file_contents={},
        )
        output = Output()

        result = run(["--hung-task-threshold", "5"], output, context)

        assert result == 1
        assert output.data["summary"]["hung_task_count"] == 6
