"""Tests for sysctl_security_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestSysctlSecurityAudit:
    """Tests for sysctl_security_audit."""

    def _create_sysctl_context(self, values: dict) -> MockContext:
        """Create a mock context with sysctl values as /proc/sys files."""
        file_contents = {
            # Mark /proc/sys as available
            "/proc/sys/kernel": "directory-marker",
        }
        for param, value in values.items():
            path = "/proc/sys/" + param.replace(".", "/")
            file_contents[path] = str(value)
        return MockContext(file_contents=file_contents)

    def test_secure_system_passes(self, capsys):
        """All checks pass on a secure system."""
        from scripts.baremetal.sysctl_security_audit import run

        # All values at recommended settings
        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "2",
                "kernel.kptr_restrict": "1",
                "kernel.dmesg_restrict": "1",
                "kernel.perf_event_paranoid": "2",
                "kernel.yama.ptrace_scope": "1",
                "vm.mmap_min_addr": "65536",
                "fs.protected_symlinks": "1",
                "fs.protected_hardlinks": "1",
                "fs.suid_dumpable": "0",
                "net.ipv4.ip_forward": "0",
                "net.ipv4.tcp_syncookies": "1",
                "net.ipv4.conf.all.rp_filter": "1",
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_insecure_system_fails(self, capsys):
        """Issues detected on an insecure system."""
        from scripts.baremetal.sysctl_security_audit import run

        # Critical ASLR disabled
        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "0",  # ASLR disabled = critical
                "kernel.kptr_restrict": "0",
                "fs.suid_dumpable": "2",
                "net.ipv4.ip_forward": "1",
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_category_filter_network(self, capsys):
        """Category filter limits checks to network only."""
        from scripts.baremetal.sysctl_security_audit import run

        context = self._create_sysctl_context(
            {
                # Kernel issue should be ignored
                "kernel.randomize_va_space": "0",
                # Network settings are good
                "net.ipv4.ip_forward": "0",
                "net.ipv4.tcp_syncookies": "1",
            }
        )
        output = Output()

        result = run(["--category", "network"], output, context)

        # Should pass since kernel issues are ignored
        assert result == 0

    def test_severity_filter_critical(self, capsys):
        """Severity filter limits checks to critical/high only."""
        from scripts.baremetal.sysctl_security_audit import run

        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "2",  # critical - good
                # low severity issues shouldn't fail with --severity high
                "net.ipv4.conf.all.log_martians": "0",  # low severity
            }
        )
        output = Output()

        result = run(["--severity", "high"], output, context)

        # Should pass since low severity are not checked
        assert result == 0

    def test_json_output_format(self, capsys):
        """JSON output contains expected structure."""
        from scripts.baremetal.sysctl_security_audit import run

        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "2",
            }
        )
        output = Output()

        result = run(["--format", "json", "--verbose"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "results" in data
        assert "total_checks" in data["summary"]
        assert "by_severity" in data["summary"]

    def test_list_checks_mode(self, capsys):
        """List checks mode shows all available checks."""
        from scripts.baremetal.sysctl_security_audit import run

        context = self._create_sysctl_context({})
        output = Output()

        result = run(["--list-checks"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "kernel.randomize_va_space" in captured.out
        assert "Total:" in captured.out

    def test_unavailable_parameter_not_failure(self, capsys):
        """Missing parameters are marked N/A but not failures."""
        from scripts.baremetal.sysctl_security_audit import run

        # Only provide one parameter, others will be "unavailable"
        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "2",  # Good
                # yama.ptrace_scope missing = unavailable
            }
        )
        output = Output()

        result = run(["--category", "kernel", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should pass - unavailable is not a failure
        assert result == 0
        assert data["summary"]["unavailable"] > 0
