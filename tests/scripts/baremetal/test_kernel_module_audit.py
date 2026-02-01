"""Tests for kernel_module_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "kernel"
PROC_FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "proc"


def load_fixture(name: str) -> str:
    """Load a fixture file from kernel directory."""
    return (FIXTURES_DIR / name).read_text()


def load_proc_fixture(name: str) -> str:
    """Load a fixture file from proc directory."""
    return (PROC_FIXTURES_DIR / name).read_text()


class TestKernelModuleAudit:
    """Tests for kernel_module_audit script."""

    def test_clean_modules_returns_0(self, capsys):
        """All clean modules returns exit code 0."""
        from scripts.baremetal.kernel_module_audit import run

        context = MockContext(
            tools_available=["lsmod", "modinfo", "uname"],
            command_outputs={
                ("lsmod",): load_fixture("modules_clean.txt"),
                ("uname", "-r"): "5.15.0-generic\n",
                ("modinfo", "ext4"): load_fixture("modinfo_ext4.txt"),
                ("modinfo", "mbcache"): load_fixture("modinfo_ext4.txt"),
                ("modinfo", "jbd2"): load_fixture("modinfo_ext4.txt"),
                ("modinfo", "sd_mod"): load_fixture("modinfo_ext4.txt"),
                ("modinfo", "ahci"): load_fixture("modinfo_ext4.txt"),
                ("modinfo", "libahci"): load_fixture("modinfo_ext4.txt"),
            },
            file_contents={
                "/proc/sys/kernel/tainted": "0\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data["summary"]["with_issues"] == 0

    def test_proprietary_module_returns_1(self, capsys):
        """Proprietary module returns exit code 1."""
        from scripts.baremetal.kernel_module_audit import run

        context = MockContext(
            tools_available=["lsmod", "modinfo", "uname"],
            command_outputs={
                ("lsmod",): load_fixture("modules_nvidia.txt"),
                ("uname", "-r"): "5.15.0-generic\n",
                ("modinfo", "nvidia_drm"): load_fixture("modinfo_nvidia.txt"),
                ("modinfo", "nvidia_modeset"): load_fixture("modinfo_nvidia.txt"),
                ("modinfo", "nvidia"): load_fixture("modinfo_nvidia.txt"),
                ("modinfo", "drm_kms_helper"): load_fixture("modinfo_ext4.txt"),
                ("modinfo", "ext4"): load_fixture("modinfo_ext4.txt"),
            },
            file_contents={
                "/proc/sys/kernel/tainted": "4096\n",
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        assert output.data["summary"]["proprietary"] > 0

    def test_missing_lsmod_returns_2(self, capsys):
        """Missing lsmod returns exit code 2."""
        from scripts.baremetal.kernel_module_audit import run

        context = MockContext(
            tools_available=[],  # No lsmod
        )
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert len(output.errors) > 0

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.kernel_module_audit import run

        context = MockContext(
            tools_available=["lsmod", "uname"],
            command_outputs={
                ("lsmod",): load_fixture("modules_clean.txt"),
                ("uname", "-r"): "5.15.0-generic\n",
            },
            file_contents={
                "/proc/sys/kernel/tainted": "0\n",
            },
        )
        output = Output()

        result = run(["--format", "json", "--no-signature-check"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "kernel_version" in data
        assert "taint_value" in data
        assert "summary" in data
        assert "modules" in data

    def test_all_flag_shows_all_modules(self, capsys):
        """--all flag shows all modules including those without issues."""
        from scripts.baremetal.kernel_module_audit import run

        context = MockContext(
            tools_available=["lsmod", "uname"],
            command_outputs={
                ("lsmod",): load_fixture("modules_clean.txt"),
                ("uname", "-r"): "5.15.0-generic\n",
            },
            file_contents={
                "/proc/sys/kernel/tainted": "0\n",
            },
        )
        output = Output()

        result = run(["--all", "--no-signature-check"], output, context)

        # With --all, we should see all modules in output
        assert result == 0
        assert len(output.data["modules"]) > 0

    def test_no_signature_check_skips_modinfo(self, capsys):
        """--no-signature-check skips modinfo calls."""
        from scripts.baremetal.kernel_module_audit import run

        context = MockContext(
            tools_available=["lsmod", "uname"],  # No modinfo needed
            command_outputs={
                ("lsmod",): load_fixture("modules_clean.txt"),
                ("uname", "-r"): "5.15.0-generic\n",
            },
            file_contents={
                "/proc/sys/kernel/tainted": "0\n",
            },
        )
        output = Output()

        result = run(["--no-signature-check"], output, context)

        assert result == 0
        assert output.data["summary"]["total"] == 6

    def test_verbose_shows_details(self, capsys):
        """Verbose mode shows module details."""
        from scripts.baremetal.kernel_module_audit import run

        context = MockContext(
            tools_available=["lsmod", "modinfo", "uname"],
            command_outputs={
                ("lsmod",): load_fixture("modules_nvidia.txt"),
                ("uname", "-r"): "5.15.0-generic\n",
                ("modinfo", "nvidia_drm"): load_fixture("modinfo_nvidia.txt"),
                ("modinfo", "nvidia_modeset"): load_fixture("modinfo_nvidia.txt"),
                ("modinfo", "nvidia"): load_fixture("modinfo_nvidia.txt"),
                ("modinfo", "drm_kms_helper"): load_fixture("modinfo_ext4.txt"),
                ("modinfo", "ext4"): load_fixture("modinfo_ext4.txt"),
            },
            file_contents={
                "/proc/sys/kernel/tainted": "4096\n",
            },
        )
        output = Output()

        result = run(["--verbose"], output, context)

        captured = capsys.readouterr()
        assert "License:" in captured.out or "Version:" in captured.out
