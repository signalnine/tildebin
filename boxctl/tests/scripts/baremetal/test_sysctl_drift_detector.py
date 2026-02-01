"""Tests for sysctl_drift_detector script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestSysctlDriftDetector:
    """Tests for sysctl_drift_detector."""

    def _create_sysctl_context(
        self, values: dict, baseline_files: dict | None = None
    ) -> MockContext:
        """Create a mock context with sysctl values as /proc/sys files."""
        file_contents = {
            # Mark /proc/sys as available
            "/proc/sys/kernel": "directory-marker",
        }
        for param, value in values.items():
            path = "/proc/sys/" + param.replace(".", "/")
            file_contents[path] = str(value)
        if baseline_files:
            file_contents.update(baseline_files)
        return MockContext(file_contents=file_contents)

    def test_no_drift_with_matching_values(self, capsys):
        """No drift when values match recommended."""
        from scripts.baremetal.sysctl_drift_detector import run

        # Provide all kernel_security category values from RECOMMENDED_VALUES
        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "2",
                "kernel.kptr_restrict": "1",
                "kernel.dmesg_restrict": "1",
                "kernel.perf_event_paranoid": "2",
                "kernel.yama.ptrace_scope": "1",
                "kernel.sysrq": "0",
            }
        )
        output = Output()

        result = run(["--category", "kernel_security"], output, context)

        assert result == 0

    def test_drift_detected_on_mismatch(self, capsys):
        """Drift detected when values differ from baseline."""
        from scripts.baremetal.sysctl_drift_detector import run

        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "0",  # Changed from 2
                "kernel.kptr_restrict": "1",
            }
        )
        output = Output()

        result = run(["--category", "kernel_security"], output, context)

        assert result == 1

    def test_custom_baseline_json(self, capsys):
        """Can load custom baseline from JSON file."""
        from scripts.baremetal.sysctl_drift_detector import run

        baseline_content = load_fixture("sysctl_baseline.json")
        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "2",
                "kernel.kptr_restrict": "1",
                "kernel.dmesg_restrict": "1",
                "net.ipv4.ip_forward": "0",
                "net.ipv4.conf.all.rp_filter": "1",
                "net.ipv4.tcp_syncookies": "1",
                "fs.protected_symlinks": "1",
                "fs.protected_hardlinks": "1",
            },
            baseline_files={"/etc/baseline.json": baseline_content},
        )
        output = Output()

        result = run(["--baseline", "/etc/baseline.json"], output, context)

        assert result == 0

    def test_custom_baseline_conf(self, capsys):
        """Can load custom baseline from sysctl.conf format."""
        from scripts.baremetal.sysctl_drift_detector import run

        baseline_content = load_fixture("sysctl_baseline.conf")
        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "2",
                "kernel.kptr_restrict": "1",
                "kernel.dmesg_restrict": "1",
                "net.ipv4.ip_forward": "0",
                "net.ipv4.conf.all.rp_filter": "1",
                "net.ipv4.tcp_syncookies": "1",
                "fs.protected_symlinks": "1",
                "fs.protected_hardlinks": "1",
            },
            baseline_files={"/etc/sysctl.baseline": baseline_content},
        )
        output = Output()

        result = run(["--baseline", "/etc/sysctl.baseline"], output, context)

        assert result == 0

    def test_pattern_filter(self, capsys):
        """Pattern filter limits parameters checked."""
        from scripts.baremetal.sysctl_drift_detector import run

        # Provide net.ipv4.tcp_syncookies which IS in RECOMMENDED_VALUES
        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "0",  # Would be drift but filtered out
                "net.ipv4.tcp_syncookies": "1",  # Matches recommended value
            }
        )
        output = Output()

        # Only check net.ipv4.tcp_syncookies parameter (which is in RECOMMENDED_VALUES)
        result = run(["--pattern", "^net\\.ipv4\\.tcp_syncookies$", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should have no drift since value matches and only that parameter is checked
        assert data["summary"]["total_drift"] == 0

    def test_json_output_format(self, capsys):
        """JSON output contains expected structure."""
        from scripts.baremetal.sysctl_drift_detector import run

        context = self._create_sysctl_context(
            {
                "kernel.randomize_va_space": "0",  # Drift
            }
        )
        output = Output()

        result = run(["--format", "json", "--category", "kernel_security"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "changed" in data
        assert "missing" in data
        assert "changed_count" in data["summary"]
        assert "missing_count" in data["summary"]

    def test_missing_baseline_file(self, capsys):
        """Error returned when baseline file not found."""
        from scripts.baremetal.sysctl_drift_detector import run

        context = self._create_sysctl_context({})
        output = Output()

        result = run(["--baseline", "/nonexistent/file.json"], output, context)

        assert result == 2
