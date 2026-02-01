"""Tests for kernel_taint script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestKernelTaint:
    """Tests for kernel_taint script."""

    def test_clean_kernel_returns_0(self, capsys):
        """Clean kernel returns exit code 0."""
        from scripts.baremetal.kernel_taint import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/tainted": load_fixture("tainted_clean.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "CLEAN" in captured.out

    def test_tainted_kernel_returns_1(self, capsys):
        """Tainted kernel returns exit code 1."""
        from scripts.baremetal.kernel_taint import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/tainted": load_fixture("tainted_proprietary.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "TAINTED" in captured.out

    def test_critical_taint_detected(self, capsys):
        """Critical taints are detected and reported."""
        from scripts.baremetal.kernel_taint import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/tainted": load_fixture("tainted_critical.txt"),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert output.data["summary"]["critical"] > 0

    def test_critical_only_flag(self, capsys):
        """--critical-only only returns 1 for critical taints."""
        from scripts.baremetal.kernel_taint import run

        # Proprietary taint only (not critical)
        context = MockContext(
            file_contents={
                "/proc/sys/kernel/tainted": load_fixture("tainted_proprietary.txt"),
            }
        )
        output = Output()

        result = run(["--critical-only"], output, context)

        # Proprietary (O bit = 4096) is a warning, not critical
        assert result == 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.kernel_taint import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/tainted": load_fixture("tainted_multiple.txt"),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "taint_value" in data
        assert "taint_string" in data
        assert "is_tainted" in data
        assert "taints" in data
        assert "summary" in data

    def test_missing_proc_file_returns_2(self, capsys):
        """Missing /proc/sys/kernel/tainted returns exit code 2."""
        from scripts.baremetal.kernel_taint import run

        context = MockContext(
            file_contents={},  # No taint file
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0

    def test_warn_only_suppresses_clean_output(self, capsys):
        """--warn-only suppresses output for clean kernel."""
        from scripts.baremetal.kernel_taint import run

        context = MockContext(
            file_contents={
                "/proc/sys/kernel/tainted": load_fixture("tainted_clean.txt"),
            }
        )
        output = Output()

        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""
