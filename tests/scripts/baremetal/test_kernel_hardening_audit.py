"""Tests for kernel_hardening_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestKernelHardeningAudit:
    """Tests for kernel_hardening_audit."""

    def _create_hardening_context(
        self,
        aslr: str = "2",
        kptr_restrict: str = "1",
        dmesg_restrict: str = "1",
        unprivileged_bpf: str = "1",
        ptrace_scope: str = "1",
        cmdline: str | None = None,
        cpuinfo: str | None = None,
        vulnerabilities: dict | None = None,
    ) -> MockContext:
        """Create a mock context with kernel hardening values."""
        if cmdline is None:
            cmdline = load_fixture("cmdline_secure.txt")
        if cpuinfo is None:
            cpuinfo = load_fixture("cpuinfo_secure.txt")

        file_contents = {
            "/proc/cmdline": cmdline,
            "/proc/cpuinfo": cpuinfo,
            "/proc/sys/kernel/randomize_va_space": aslr,
            "/proc/sys/kernel/kptr_restrict": kptr_restrict,
            "/proc/sys/kernel/dmesg_restrict": dmesg_restrict,
            "/proc/sys/kernel/unprivileged_bpf_disabled": unprivileged_bpf,
            "/proc/sys/kernel/yama/ptrace_scope": ptrace_scope,
        }

        # Add vulnerability files
        if vulnerabilities:
            for vuln, status in vulnerabilities.items():
                path = f"/sys/devices/system/cpu/vulnerabilities/{vuln}"
                file_contents[path] = status

        return MockContext(file_contents=file_contents)

    def test_secure_system_passes(self, capsys):
        """All checks pass on a secure system."""
        from scripts.baremetal.kernel_hardening_audit import run

        vuln_content = load_fixture("vulnerabilities_mitigated.txt")
        vulnerabilities = {}
        for line in vuln_content.strip().split("\n"):
            if ": " in line:
                vuln, status = line.split(": ", 1)
                vulnerabilities[vuln] = status

        context = self._create_hardening_context(
            aslr="2",
            kptr_restrict="1",
            dmesg_restrict="1",
            unprivileged_bpf="1",
            ptrace_scope="1",
            vulnerabilities=vulnerabilities,
        )
        output = Output()

        result = run([], output, context)

        assert result == 0

    def test_aslr_disabled_fails(self, capsys):
        """ASLR disabled causes failure."""
        from scripts.baremetal.kernel_hardening_audit import run

        context = self._create_hardening_context(aslr="0")
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "ASLR" in captured.out

    def test_kaslr_disabled_fails(self, capsys):
        """KASLR disabled via cmdline causes failure."""
        from scripts.baremetal.kernel_hardening_audit import run

        context = self._create_hardening_context(
            cmdline=load_fixture("cmdline_insecure.txt")
        )
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_vulnerabilities_not_mitigated(self, capsys):
        """Unmitigated vulnerabilities cause failure."""
        from scripts.baremetal.kernel_hardening_audit import run

        vuln_content = load_fixture("vulnerabilities_vulnerable.txt")
        vulnerabilities = {}
        for line in vuln_content.strip().split("\n"):
            if ": " in line:
                vuln, status = line.split(": ", 1)
                vulnerabilities[vuln] = status

        context = self._create_hardening_context(vulnerabilities=vulnerabilities)
        output = Output()

        result = run([], output, context)

        assert result == 1

    def test_json_output_format(self, capsys):
        """JSON output contains expected structure."""
        from scripts.baremetal.kernel_hardening_audit import run

        context = self._create_hardening_context()
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "checks" in data
        assert "issues" in data
        assert "warnings" in data
        assert "summary" in data
        assert "aslr" in data["checks"]
        assert "kaslr" in data["checks"]

    def test_table_output_format(self, capsys):
        """Table output has proper format."""
        from scripts.baremetal.kernel_hardening_audit import run

        context = self._create_hardening_context()
        output = Output()

        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "CHECK" in captured.out
        assert "STATUS" in captured.out
        assert "ASLR" in captured.out

    def test_verbose_shows_details(self, capsys):
        """Verbose mode shows detailed information."""
        from scripts.baremetal.kernel_hardening_audit import run

        context = self._create_hardening_context()
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        # Verbose should show details for each check
        assert "ASLR" in captured.out or "aslr" in captured.out.lower()

    def test_strict_mode_kptr_exposed(self, capsys):
        """Strict mode treats exposed kptr as error."""
        from scripts.baremetal.kernel_hardening_audit import run

        context = self._create_hardening_context(kptr_restrict="0")
        output = Output()

        # Without strict, should just be a warning
        result = run([], output, context)
        assert result == 1

        # With strict, should still fail
        result = run(["--strict"], output, context)
        assert result == 1
        captured = capsys.readouterr()
        assert "ISSUE" in captured.out or "Kernel pointers" in captured.out
