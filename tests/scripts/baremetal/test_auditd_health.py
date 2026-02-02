"""Tests for auditd_health script."""

import pytest

from boxctl.core.output import Output


class TestAuditdHealth:
    """Tests for auditd_health script."""

    def test_missing_auditctl_returns_error(self, mock_context):
        """Returns exit code 2 when auditctl not available."""
        from scripts.baremetal import auditd_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = auditd_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("auditctl" in e.lower() for e in output.errors)

    def test_auditd_running_healthy(self, mock_context):
        """Returns 0 when auditd is running and healthy."""
        from scripts.baremetal import auditd_health

        ctx = mock_context(
            tools_available=["auditctl", "systemctl", "pgrep", "ls"],
            command_outputs={
                ("systemctl", "is-active", "auditd"): "active\n",
                ("auditctl", "-s"): "enabled 1\nfailure 1\npid 1234\nlost 0\nbacklog 0\nbacklog_limit 8192\n",
                ("auditctl", "-l"): "-w /etc/passwd -p wa\n-w /etc/shadow -p wa\n",
                ("ls", "-la", "/var/log/audit"): "total 12\ndrwx------ 2 root root\n-rw------- 1 root root\n",
            },
            file_contents={
                "/var/log/audit/audit.log": "log content here",
            }
        )
        output = Output()

        exit_code = auditd_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["service_status"]["running"] is True
        assert output.data["rules_loaded"] == 2
        assert output.summary == "audit daemon healthy"

    def test_auditd_not_running(self, mock_context):
        """Returns 1 when auditd is not running."""
        from scripts.baremetal import auditd_health

        ctx = mock_context(
            tools_available=["auditctl", "systemctl", "pgrep", "ls"],
            command_outputs={
                ("systemctl", "is-active", "auditd"): "inactive\n",
                ("pgrep", "-x", "auditd"): "",
                ("auditctl", "-s"): "enabled 0\nfailure 1\nlost 0\nbacklog 0\nbacklog_limit 8192\n",
                ("auditctl", "-l"): "No rules\n",
                ("ls", "-la", "/var/log/audit"): "total 0\n",
            },
            file_contents={}
        )
        output = Output()

        exit_code = auditd_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["service_status"]["running"] is False
        assert len(output.data["issues"]) > 0
        # Should have critical issue for not running
        assert any(i["severity"] == "critical" for i in output.data["issues"])

    def test_audit_events_lost(self, mock_context):
        """Returns 1 when audit events have been lost."""
        from scripts.baremetal import auditd_health

        ctx = mock_context(
            tools_available=["auditctl", "systemctl", "pgrep", "ls"],
            command_outputs={
                ("systemctl", "is-active", "auditd"): "active\n",
                ("auditctl", "-s"): "enabled 1\nfailure 1\nlost 100\nbacklog 0\nbacklog_limit 8192\n",
                ("auditctl", "-l"): "-w /etc/passwd -p wa\n",
                ("ls", "-la", "/var/log/audit"): "total 12\ndrwx------ 2 root root\n",
            },
            file_contents={
                "/var/log/audit/audit.log": "log content",
            }
        )
        output = Output()

        exit_code = auditd_health.run([], output, ctx)

        assert exit_code == 1
        # Should have warning for lost events
        assert any("lost" in i["message"].lower() for i in output.data["issues"])

    def test_min_rules_check(self, mock_context):
        """Returns 1 when fewer rules than minimum are loaded."""
        from scripts.baremetal import auditd_health

        ctx = mock_context(
            tools_available=["auditctl", "systemctl", "pgrep", "ls"],
            command_outputs={
                ("systemctl", "is-active", "auditd"): "active\n",
                ("auditctl", "-s"): "enabled 1\nfailure 1\nlost 0\nbacklog 0\nbacklog_limit 8192\n",
                ("auditctl", "-l"): "-w /etc/passwd -p wa\n",
                ("ls", "-la", "/var/log/audit"): "total 12\ndrwx------ 2 root root\n",
            },
            file_contents={
                "/var/log/audit/audit.log": "log content",
            }
        )
        output = Output()

        exit_code = auditd_health.run(["--min-rules", "5"], output, ctx)

        assert exit_code == 1
        assert any("rules" in i["message"].lower() for i in output.data["issues"])

    def test_verbose_shows_rules(self, mock_context):
        """--verbose includes audit rules in output."""
        from scripts.baremetal import auditd_health

        ctx = mock_context(
            tools_available=["auditctl", "systemctl", "pgrep", "ls"],
            command_outputs={
                ("systemctl", "is-active", "auditd"): "active\n",
                ("auditctl", "-s"): "enabled 1\nfailure 1\nlost 0\nbacklog 0\nbacklog_limit 8192\n",
                ("auditctl", "-l"): "-w /etc/passwd -p wa\n-w /etc/shadow -p wa\n",
                ("ls", "-la", "/var/log/audit"): "total 12\ndrwx------ 2 root root\n",
            },
            file_contents={
                "/var/log/audit/audit.log": "log content",
            }
        )
        output = Output()

        exit_code = auditd_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "audit_rules" in output.data
        assert len(output.data["audit_rules"]) == 2

    def test_high_backlog_warning(self, mock_context):
        """Returns 1 when audit backlog is high."""
        from scripts.baremetal import auditd_health

        ctx = mock_context(
            tools_available=["auditctl", "systemctl", "pgrep", "ls"],
            command_outputs={
                ("systemctl", "is-active", "auditd"): "active\n",
                ("auditctl", "-s"): "enabled 1\nfailure 1\nlost 0\nbacklog 7000\nbacklog_limit 8192\n",
                ("auditctl", "-l"): "-w /etc/passwd -p wa\n",
                ("ls", "-la", "/var/log/audit"): "total 12\ndrwx------ 2 root root\n",
            },
            file_contents={
                "/var/log/audit/audit.log": "log content",
            }
        )
        output = Output()

        exit_code = auditd_health.run([], output, ctx)

        assert exit_code == 1
        assert any("backlog" in i["message"].lower() for i in output.data["issues"])
