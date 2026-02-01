"""Tests for systemd_journal_analyzer script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "systemd"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class FlexibleMockContext(MockContext):
    """MockContext that handles variable journalctl --since arguments."""

    def run(self, cmd, **kwargs):
        self.commands_run.append(cmd)

        # Handle journalctl commands with variable --since timestamps
        if cmd[0] == "journalctl":
            # Find the fixture to use based on other parameters
            if "-u" in cmd:
                unit_idx = cmd.index("-u") + 1
                if unit_idx < len(cmd):
                    unit = cmd[unit_idx]
                    if unit in self._unit_outputs:
                        import subprocess
                        return subprocess.CompletedProcess(
                            cmd, returncode=0,
                            stdout=self._unit_outputs[unit],
                            stderr=""
                        )
            # Default journalctl output
            import subprocess
            return subprocess.CompletedProcess(
                cmd, returncode=0,
                stdout=getattr(self, "_journal_output", ""),
                stderr=""
            )

        # Handle systemctl commands
        key = tuple(cmd)
        if key in self.command_outputs:
            output = self.command_outputs[key]
            import subprocess
            return subprocess.CompletedProcess(cmd, returncode=0, stdout=output, stderr="")

        raise KeyError(f"No mock output for command: {cmd}")


class TestSystemdJournalAnalyzer:
    """Tests for systemd_journal_analyzer."""

    def test_missing_journalctl_returns_error(self):
        """Returns exit code 2 when journalctl not available."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = MockContext(tools_available=["systemctl"])
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("journalctl" in e.lower() for e in output.errors)

    def test_missing_systemctl_returns_error(self):
        """Returns exit code 2 when systemctl not available."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = MockContext(tools_available=["journalctl"])
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("systemctl" in e.lower() for e in output.errors)

    def test_healthy_journal_returns_zero(self):
        """Returns 0 when no issues in journal."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = FlexibleMockContext(
            tools_available=["journalctl", "systemctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain"): "",
            },
        )
        ctx._journal_output = load_fixture("journal_healthy.txt")
        ctx._unit_outputs = {}
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_issues"] == 0

    def test_service_failures_detected(self):
        """Detects service failures in journal."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = FlexibleMockContext(
            tools_available=["journalctl", "systemctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain"): "nginx.service loaded failed failed\n",
            },
        )
        ctx._journal_output = load_fixture("journal_failures.txt")
        ctx._unit_outputs = {}
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["critical_count"] >= 1
        assert "service_failure" in output.data["findings"]

    def test_oom_kills_detected(self):
        """Detects OOM kills in journal."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = FlexibleMockContext(
            tools_available=["journalctl", "systemctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain"): "",
            },
        )
        ctx._journal_output = load_fixture("journal_oom.txt")
        ctx._unit_outputs = {}
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        assert "oom_kill" in output.data["findings"]
        assert len(output.data["findings"]["oom_kill"]) >= 1

    def test_auth_failures_detected(self):
        """Detects authentication failures in journal."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = FlexibleMockContext(
            tools_available=["journalctl", "systemctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain"): "",
            },
        )
        ctx._journal_output = load_fixture("journal_auth_failures.txt")
        ctx._unit_outputs = {}
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        assert "auth_failure" in output.data["findings"]

    def test_custom_since_parameter(self):
        """Custom --since parameter is used."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = FlexibleMockContext(
            tools_available=["journalctl", "systemctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain"): "",
            },
        )
        ctx._journal_output = ""
        ctx._unit_outputs = {}
        output = Output()

        exit_code = run(["--since", "1h"], output, ctx)

        # Verify the --since parameter was passed to journalctl
        journal_cmds = [cmd for cmd in ctx.commands_run if cmd[0] == "journalctl"]
        assert any("--since" in cmd and "-1h" in cmd for cmd in journal_cmds)

    def test_unit_filter(self):
        """--unit parameter filters to specific unit."""
        from scripts.baremetal.systemd_journal_analyzer import run

        ctx = FlexibleMockContext(
            tools_available=["journalctl", "systemctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-legend", "--plain"): "",
            },
        )
        ctx._journal_output = ""
        ctx._unit_outputs = {"nginx.service": load_fixture("journal_healthy.txt")}
        output = Output()

        exit_code = run(["--unit", "nginx.service"], output, ctx)

        # Verify -u flag was passed
        journal_cmds = [cmd for cmd in ctx.commands_run if cmd[0] == "journalctl"]
        assert any("-u" in cmd and "nginx.service" in cmd for cmd in journal_cmds)
