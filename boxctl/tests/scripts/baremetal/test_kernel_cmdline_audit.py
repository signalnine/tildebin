"""Tests for kernel_cmdline_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestKernelCmdlineAudit:
    """Tests for kernel_cmdline_audit script."""

    def test_secure_cmdline_returns_0(self, capsys):
        """Secure cmdline returns exit code 0."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={
                "/proc/cmdline": load_fixture("cmdline_secure.txt"),
            }
        )
        output = Output()

        result = run(["--skip-performance"], output, context)

        assert result == 0
        assert output.data["summary"]["critical"] == 0
        assert output.data["summary"]["warning"] == 0

    def test_insecure_cmdline_returns_1(self, capsys):
        """Insecure cmdline returns exit code 1."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={
                "/proc/cmdline": load_fixture("cmdline_insecure.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        # Should detect mitigations=off as critical
        assert output.data["summary"]["critical"] > 0

    def test_mitigations_off_is_critical(self, capsys):
        """mitigations=off is detected as critical."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={
                "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 mitigations=off",
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        critical = [f for f in output.data["findings"] if f["severity"] == "CRITICAL"]
        assert any(f["parameter"] == "mitigations" for f in critical)

    def test_nokaslr_is_warning(self, capsys):
        """nokaslr is detected as warning."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={
                "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 nokaslr",
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        warnings = [f for f in output.data["findings"] if f["severity"] == "WARNING"]
        assert any(f["parameter"] == "nokaslr" for f in warnings)

    def test_debug_param_detected(self, capsys):
        """Debug parameter is detected."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={
                "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 debug",
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        findings = output.data["findings"]
        assert any(f["parameter"] == "debug" for f in findings)

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={
                "/proc/cmdline": load_fixture("cmdline_secure.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "cmdline" in data
        assert "parameter_count" in data
        assert "parameters" in data
        assert "summary" in data
        assert "findings" in data

    def test_missing_proc_cmdline_returns_2(self, capsys):
        """Missing /proc/cmdline returns exit code 2."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={},  # No cmdline file
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0

    def test_performance_params_detected(self, capsys):
        """Performance parameters are detected as INFO."""
        from scripts.baremetal.kernel_cmdline_audit import run

        context = MockContext(
            file_contents={
                "/proc/cmdline": load_fixture("cmdline_performance.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        # Performance params are INFO only, so should return 0
        assert result == 0
        info = [f for f in output.data["findings"] if f["severity"] == "INFO"]
        assert len(info) > 0
