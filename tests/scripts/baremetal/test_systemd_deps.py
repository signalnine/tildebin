"""Tests for systemd_deps script."""

import pytest

from boxctl.core.output import Output


SYSTEMCTL_SHOW_HEALTHY = """LoadState=loaded
ActiveState=active
SubState=running
"""

SYSTEMCTL_SHOW_FAILED = """LoadState=loaded
ActiveState=failed
SubState=failed
"""

SYSTEMCTL_SHOW_INACTIVE = """LoadState=loaded
ActiveState=inactive
SubState=dead
"""

SYSTEMCTL_SHOW_MASKED = """LoadState=masked
ActiveState=inactive
SubState=dead
"""

SYSTEMCTL_SHOW_NOT_FOUND = """LoadState=not-found
ActiveState=inactive
SubState=dead
"""

SYSTEMCTL_LIST_UNITS = """sshd.service              loaded active running OpenSSH daemon
docker.service            loaded active running Docker daemon
nginx.service             loaded failed failed  nginx web server
"""

SYSTEMCTL_LIST_UNITS_EMPTY = ""

SYSTEMCTL_FAILED = """nginx.service             loaded failed failed nginx web server
"""

SYSTEMCTL_FAILED_EMPTY = ""


class TestSystemdDeps:
    """Tests for systemd_deps script."""

    def test_missing_systemctl_returns_error(self, mock_context):
        """Returns exit code 2 when systemctl not available."""
        from scripts.baremetal import systemd_deps

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = systemd_deps.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("systemctl" in e.lower() for e in output.errors)

    def test_healthy_unit(self, mock_context):
        """Returns 0 when unit has no dependency issues."""
        from scripts.baremetal import systemd_deps

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "show", "sshd.service", "--property=LoadState", "--no-pager"): "LoadState=loaded",
                ("systemctl", "show", "sshd.service", "--property=ActiveState", "--no-pager"): "ActiveState=active",
                ("systemctl", "show", "sshd.service", "--property=SubState", "--no-pager"): "SubState=running",
                ("systemctl", "show", "sshd.service", "--property=Requires", "--no-pager"): "Requires=",
                ("systemctl", "show", "sshd.service", "--property=Wants", "--no-pager"): "Wants=",
                ("systemctl", "show", "sshd.service", "--property=BindsTo", "--no-pager"): "BindsTo=",
                ("systemctl", "show", "sshd.service", "--property=PartOf", "--no-pager"): "PartOf=",
                ("systemctl", "show", "sshd.service", "--property=Requisite", "--no-pager"): "Requisite=",
                ("systemctl", "show", "sshd.service", "--property=Conflicts", "--no-pager"): "Conflicts=",
                ("systemctl", "show", "sshd.service", "--property=Before", "--no-pager"): "Before=",
                ("systemctl", "show", "sshd.service", "--property=After", "--no-pager"): "After=",
            }
        )
        output = Output()

        exit_code = systemd_deps.run(["--unit", "sshd.service"], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['units_with_issues'] == 0

    def test_failed_dependency_detected(self, mock_context):
        """Detects when a required dependency is in failed state."""
        from scripts.baremetal import systemd_deps

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                # Main unit
                ("systemctl", "show", "nginx.service", "--property=LoadState", "--no-pager"): "LoadState=loaded",
                ("systemctl", "show", "nginx.service", "--property=ActiveState", "--no-pager"): "ActiveState=active",
                ("systemctl", "show", "nginx.service", "--property=SubState", "--no-pager"): "SubState=running",
                ("systemctl", "show", "nginx.service", "--property=Requires", "--no-pager"): "Requires=network.service",
                ("systemctl", "show", "nginx.service", "--property=Wants", "--no-pager"): "Wants=",
                ("systemctl", "show", "nginx.service", "--property=BindsTo", "--no-pager"): "BindsTo=",
                ("systemctl", "show", "nginx.service", "--property=PartOf", "--no-pager"): "PartOf=",
                ("systemctl", "show", "nginx.service", "--property=Requisite", "--no-pager"): "Requisite=",
                ("systemctl", "show", "nginx.service", "--property=Conflicts", "--no-pager"): "Conflicts=",
                ("systemctl", "show", "nginx.service", "--property=Before", "--no-pager"): "Before=",
                ("systemctl", "show", "nginx.service", "--property=After", "--no-pager"): "After=",
                # Dependency
                ("systemctl", "show", "network.service", "--property=LoadState", "--no-pager"): "LoadState=loaded",
                ("systemctl", "show", "network.service", "--property=ActiveState", "--no-pager"): "ActiveState=failed",
                ("systemctl", "show", "network.service", "--property=SubState", "--no-pager"): "SubState=failed",
            }
        )
        output = Output()

        exit_code = systemd_deps.run(["--unit", "nginx.service"], output, ctx)

        assert exit_code == 1
        assert output.data['summary']['units_with_issues'] > 0
        # Check that failed dependency issue is recorded
        issues = output.data['units'][0]['issues']
        assert any(i['type'] == 'failed_dependency' for i in issues)

    def test_missing_dependency_detected(self, mock_context):
        """Detects when a required dependency is not found."""
        from scripts.baremetal import systemd_deps

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                # Main unit
                ("systemctl", "show", "app.service", "--property=LoadState", "--no-pager"): "LoadState=loaded",
                ("systemctl", "show", "app.service", "--property=ActiveState", "--no-pager"): "ActiveState=active",
                ("systemctl", "show", "app.service", "--property=SubState", "--no-pager"): "SubState=running",
                ("systemctl", "show", "app.service", "--property=Requires", "--no-pager"): "Requires=missing.service",
                ("systemctl", "show", "app.service", "--property=Wants", "--no-pager"): "Wants=",
                ("systemctl", "show", "app.service", "--property=BindsTo", "--no-pager"): "BindsTo=",
                ("systemctl", "show", "app.service", "--property=PartOf", "--no-pager"): "PartOf=",
                ("systemctl", "show", "app.service", "--property=Requisite", "--no-pager"): "Requisite=",
                ("systemctl", "show", "app.service", "--property=Conflicts", "--no-pager"): "Conflicts=",
                ("systemctl", "show", "app.service", "--property=Before", "--no-pager"): "Before=",
                ("systemctl", "show", "app.service", "--property=After", "--no-pager"): "After=",
                # Missing dependency
                ("systemctl", "show", "missing.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "missing.service", "--property=ActiveState", "--no-pager"): "ActiveState=inactive",
                ("systemctl", "show", "missing.service", "--property=SubState", "--no-pager"): "SubState=dead",
            }
        )
        output = Output()

        exit_code = systemd_deps.run(["--unit", "app.service"], output, ctx)

        assert exit_code == 1
        issues = output.data['units'][0]['issues']
        assert any(i['type'] == 'missing_dependency' for i in issues)

    def test_masked_dependency_detected(self, mock_context):
        """Detects when a required dependency is masked."""
        from scripts.baremetal import systemd_deps

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                # Main unit
                ("systemctl", "show", "app.service", "--property=LoadState", "--no-pager"): "LoadState=loaded",
                ("systemctl", "show", "app.service", "--property=ActiveState", "--no-pager"): "ActiveState=active",
                ("systemctl", "show", "app.service", "--property=SubState", "--no-pager"): "SubState=running",
                ("systemctl", "show", "app.service", "--property=Requires", "--no-pager"): "Requires=masked.service",
                ("systemctl", "show", "app.service", "--property=Wants", "--no-pager"): "Wants=",
                ("systemctl", "show", "app.service", "--property=BindsTo", "--no-pager"): "BindsTo=",
                ("systemctl", "show", "app.service", "--property=PartOf", "--no-pager"): "PartOf=",
                ("systemctl", "show", "app.service", "--property=Requisite", "--no-pager"): "Requisite=",
                ("systemctl", "show", "app.service", "--property=Conflicts", "--no-pager"): "Conflicts=",
                ("systemctl", "show", "app.service", "--property=Before", "--no-pager"): "Before=",
                ("systemctl", "show", "app.service", "--property=After", "--no-pager"): "After=",
                # Masked dependency
                ("systemctl", "show", "masked.service", "--property=LoadState", "--no-pager"): "LoadState=masked",
                ("systemctl", "show", "masked.service", "--property=ActiveState", "--no-pager"): "ActiveState=inactive",
                ("systemctl", "show", "masked.service", "--property=SubState", "--no-pager"): "SubState=dead",
            }
        )
        output = Output()

        exit_code = systemd_deps.run(["--unit", "app.service"], output, ctx)

        assert exit_code == 1
        issues = output.data['units'][0]['issues']
        assert any(i['type'] == 'masked_dependency' for i in issues)

    def test_no_units_to_analyze(self, mock_context):
        """Returns 0 when no units to analyze."""
        from scripts.baremetal import systemd_deps

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "--failed", "--no-legend", "--no-pager"): "",
                ("systemctl", "show", "sshd.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "sshd.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "sshd.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "NetworkManager.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "NetworkManager.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "NetworkManager.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "systemd-networkd.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "systemd-networkd.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "systemd-networkd.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "docker.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "docker.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "docker.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "containerd.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "containerd.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "containerd.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "kubelet.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "kubelet.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "kubelet.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "cron.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "cron.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "cron.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "rsyslog.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "rsyslog.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "rsyslog.service", "--property=SubState", "--no-pager"): "",
                ("systemctl", "show", "systemd-journald.service", "--property=LoadState", "--no-pager"): "LoadState=not-found",
                ("systemctl", "show", "systemd-journald.service", "--property=ActiveState", "--no-pager"): "",
                ("systemctl", "show", "systemd-journald.service", "--property=SubState", "--no-pager"): "",
            }
        )
        output = Output()

        exit_code = systemd_deps.run([], output, ctx)

        assert exit_code == 0
        assert output.data['summary']['total_units'] == 0

    def test_verbose_output(self, mock_context):
        """--verbose includes detailed dependency information."""
        from scripts.baremetal import systemd_deps

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "show", "sshd.service", "--property=LoadState", "--no-pager"): "LoadState=loaded",
                ("systemctl", "show", "sshd.service", "--property=ActiveState", "--no-pager"): "ActiveState=active",
                ("systemctl", "show", "sshd.service", "--property=SubState", "--no-pager"): "SubState=running",
                ("systemctl", "show", "sshd.service", "--property=Requires", "--no-pager"): "Requires=",
                ("systemctl", "show", "sshd.service", "--property=Wants", "--no-pager"): "Wants=",
                ("systemctl", "show", "sshd.service", "--property=BindsTo", "--no-pager"): "BindsTo=",
                ("systemctl", "show", "sshd.service", "--property=PartOf", "--no-pager"): "PartOf=",
                ("systemctl", "show", "sshd.service", "--property=Requisite", "--no-pager"): "Requisite=",
                ("systemctl", "show", "sshd.service", "--property=Conflicts", "--no-pager"): "Conflicts=",
                ("systemctl", "show", "sshd.service", "--property=Before", "--no-pager"): "Before=",
                ("systemctl", "show", "sshd.service", "--property=After", "--no-pager"): "After=network.target",
            }
        )
        output = Output()

        exit_code = systemd_deps.run(["--unit", "sshd.service", "--verbose"], output, ctx)

        assert exit_code == 0
        assert 'units' in output.data
        assert len(output.data['units']) > 0
        assert 'dependencies' in output.data['units'][0]
