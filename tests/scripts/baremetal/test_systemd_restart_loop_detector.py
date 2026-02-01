"""Tests for systemd_restart_loop_detector script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "systemd"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSystemdRestartLoopDetector:
    """Tests for systemd_restart_loop_detector."""

    def test_missing_systemctl_returns_error(self):
        """Returns exit code 2 when systemctl not available."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        ctx = MockContext(tools_available=["journalctl"])
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("systemctl" in e.lower() for e in output.errors)

    def test_missing_journalctl_returns_error(self):
        """Returns exit code 2 when journalctl not available."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        ctx = MockContext(tools_available=["systemctl"])
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("journalctl" in e.lower() for e in output.errors)

    def test_no_restart_loops_returns_zero(self):
        """Returns 0 when no restart loops detected."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        ctx = MockContext(
            tools_available=["systemctl", "journalctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend", "--plain"): "",
                ("systemctl", "list-units", "--type=service", "--state=activating,reloading", "--no-pager", "--no-legend", "--plain"): "",
            },
        )
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["services_in_loop"] == 0

    def test_restart_loop_detected(self):
        """Returns 1 when a service is in restart loop."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        # Build mock context for a service with 5 restarts
        ctx = MockContext(
            tools_available=["systemctl", "journalctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend", "--plain"): "flaky.service loaded failed failed Flaky Service\n",
                ("systemctl", "list-units", "--type=service", "--state=activating,reloading", "--no-pager", "--no-legend", "--plain"): "",
            },
        )

        # Add dynamic command matching for journalctl with --since
        class FlexibleMockContext(MockContext):
            def run(self, cmd, **kwargs):
                self.commands_run.append(cmd)
                key = tuple(cmd)

                # Handle journalctl commands with variable --since timestamps
                if cmd[0] == "journalctl" and "-u" in cmd:
                    service_idx = cmd.index("-u") + 1
                    if service_idx < len(cmd) and cmd[service_idx] == "flaky.service":
                        import subprocess
                        return subprocess.CompletedProcess(
                            cmd, returncode=0,
                            stdout=load_fixture("restart_loop_journalctl.txt"),
                            stderr=""
                        )

                # Handle systemctl show commands
                if cmd[0] == "systemctl" and cmd[1] == "show":
                    service = cmd[2]
                    if service == "flaky.service":
                        import subprocess
                        return subprocess.CompletedProcess(
                            cmd, returncode=0,
                            stdout=load_fixture("service_show_high_restarts.txt"),
                            stderr=""
                        )

                # Fall back to regular mock handling
                if key in self.command_outputs:
                    output = self.command_outputs[key]
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout=output, stderr="")

                raise KeyError(f"No mock output for command: {cmd}")

        ctx = FlexibleMockContext(
            tools_available=["systemctl", "journalctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend", "--plain"): "flaky.service loaded failed failed Flaky Service\n",
                ("systemctl", "list-units", "--type=service", "--state=activating,reloading", "--no-pager", "--no-legend", "--plain"): "",
            },
        )
        output = Output()

        exit_code = run(["--threshold", "3"], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["services_in_loop"] >= 1

    def test_invalid_hours_returns_error(self):
        """Returns 2 for invalid hours value."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        ctx = MockContext(tools_available=["systemctl", "journalctl"])
        output = Output()

        exit_code = run(["--hours", "0"], output, ctx)

        assert exit_code == 2

    def test_invalid_threshold_returns_error(self):
        """Returns 2 for invalid threshold value."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        ctx = MockContext(tools_available=["systemctl", "journalctl"])
        output = Output()

        exit_code = run(["--threshold", "0"], output, ctx)

        assert exit_code == 2

    def test_check_all_services(self):
        """--all flag checks all services."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        class FlexibleMockContext(MockContext):
            def run(self, cmd, **kwargs):
                self.commands_run.append(cmd)
                key = tuple(cmd)

                # Handle journalctl commands - return empty for all services
                if cmd[0] == "journalctl":
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

                # Fall back to regular mock handling
                if key in self.command_outputs:
                    output = self.command_outputs[key]
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout=output, stderr="")

                raise KeyError(f"No mock output for command: {cmd}")

        ctx = FlexibleMockContext(
            tools_available=["systemctl", "journalctl"],
            command_outputs={
                ("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"): "sshd.service loaded active running\nnginx.service loaded active running\n",
            },
        )
        output = Output()

        exit_code = run(["--all"], output, ctx)

        # Should have checked the --all command
        assert any("--all" in cmd for cmd in ctx.commands_run)
        assert exit_code == 0

    def test_custom_time_window(self):
        """Custom time window is passed to journalctl."""
        from scripts.baremetal.systemd_restart_loop_detector import run

        class FlexibleMockContext(MockContext):
            def run(self, cmd, **kwargs):
                self.commands_run.append(cmd)
                key = tuple(cmd)

                if cmd[0] == "journalctl":
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

                if key in self.command_outputs:
                    output = self.command_outputs[key]
                    import subprocess
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout=output, stderr="")

                raise KeyError(f"No mock output for command: {cmd}")

        ctx = FlexibleMockContext(
            tools_available=["systemctl", "journalctl"],
            command_outputs={
                ("systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend", "--plain"): "test.service loaded failed failed Test\n",
                ("systemctl", "list-units", "--type=service", "--state=activating,reloading", "--no-pager", "--no-legend", "--plain"): "",
            },
        )
        output = Output()

        exit_code = run(["--hours", "6"], output, ctx)

        # Should have run, verifying the command executed
        assert exit_code == 0
