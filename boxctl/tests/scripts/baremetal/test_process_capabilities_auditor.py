"""Tests for process_capabilities_auditor script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestProcessCapabilitiesAuditor:
    """Tests for process_capabilities_auditor."""

    def test_no_privileged_processes_returns_zero(self, capsys):
        """No privileged processes returns exit code 0."""
        from scripts.baremetal.process_capabilities_auditor import run

        # Mock /proc with process that has no capabilities
        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/1234/comm": "python3\n",
                "/proc/1234/cmdline": "python3\x00script.py\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "0" in captured.out or "No" in captured.out

    def test_high_risk_process_returns_one(self, capsys):
        """Process with high-risk capabilities returns exit code 1."""
        from scripts.baremetal.process_capabilities_auditor import run

        # CAP_SYS_ADMIN is bit 21 = 0x200000
        context = MockContext(
            file_contents={
                "/proc/3000/status": """Name:\tprivileged_app
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000200000
CapEff:\t0000000000200000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/3000/comm": "privileged_app\n",
                "/proc/3000/cmdline": "privileged_app\x00",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/3000"] if root == "/proc" else []
        )

        output = Output()
        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CAP_SYS_ADMIN" in captured.out or "HIGH RISK" in captured.out

    def test_root_process_excluded_by_default(self, capsys):
        """Root processes are excluded by default."""
        from scripts.baremetal.process_capabilities_auditor import run

        context = MockContext(
            file_contents={
                "/proc/1/status": """Name:\tsystemd
Uid:\t0\t0\t0\t0
CapInh:\t0000000000000000
CapPrm:\t000001ffffffffff
CapEff:\t000001ffffffffff
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/1/comm": "systemd\n",
            }
        )
        context.glob = lambda pattern, root="/": ["/proc/1"] if root == "/proc" else []

        output = Output()
        result = run([], output, context)

        # Should return 0 because root is excluded
        assert result == 0

    def test_include_root_flag(self, capsys):
        """Include-root flag includes root processes."""
        from scripts.baremetal.process_capabilities_auditor import run

        context = MockContext(
            file_contents={
                "/proc/1/status": """Name:\tsystemd
Uid:\t0\t0\t0\t0
CapInh:\t0000000000000000
CapPrm:\t000001ffffffffff
CapEff:\t000001ffffffffff
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/1/comm": "systemd\n",
            }
        )
        context.glob = lambda pattern, root="/": ["/proc/1"] if root == "/proc" else []

        output = Output()
        result = run(["--include-root"], output, context)

        # Should return 1 because root has high-risk caps
        assert result == 1
        captured = capsys.readouterr()
        assert "systemd" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.process_capabilities_auditor import run

        # CAP_NET_RAW is bit 13 = 0x2000
        context = MockContext(
            file_contents={
                "/proc/2000/status": """Name:\tping
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000002000
CapEff:\t0000000000002000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/2000/comm": "ping\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/2000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "summary" in data
        assert "processes" in data
        assert "high_risk_capabilities" in data
        assert data["summary"]["total_privileged_processes"] == 1

    def test_capability_filter(self, capsys):
        """Capability filter only shows processes with specified cap."""
        from scripts.baremetal.process_capabilities_auditor import run

        context = MockContext(
            file_contents={
                # Process with CAP_NET_RAW
                "/proc/2000/status": """Name:\tping
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000002000
CapEff:\t0000000000002000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/2000/comm": "ping\n",
                # Process with CAP_SYS_ADMIN
                "/proc/3000/status": """Name:\tother_app
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000200000
CapEff:\t0000000000200000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/3000/comm": "other_app\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/2000", "/proc/3000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--cap", "CAP_NET_RAW", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should only show ping with CAP_NET_RAW
        assert data["summary"]["total_privileged_processes"] == 1
        assert data["processes"][0]["comm"] == "ping"

    def test_warn_only_silent_when_no_high_risk(self, capsys):
        """Warn-only mode produces no output when no high-risk processes."""
        from scripts.baremetal.process_capabilities_auditor import run

        context = MockContext(
            file_contents={
                "/proc/1234/status": """Name:\tpython3
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1234"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_list_caps_flag(self, capsys):
        """List-caps flag shows all capabilities."""
        from scripts.baremetal.process_capabilities_auditor import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--list-caps"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "CAP_SYS_ADMIN" in captured.out
        assert "CAP_NET_RAW" in captured.out
        assert "HIGH RISK" in captured.out

    def test_invalid_capability_returns_two(self, capsys):
        """Invalid capability name returns exit code 2."""
        from scripts.baremetal.process_capabilities_auditor import run

        context = MockContext()
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--cap", "CAP_INVALID"], output, context)

        assert result == 2

    def test_table_format(self, capsys):
        """Table format produces formatted output."""
        from scripts.baremetal.process_capabilities_auditor import run

        # CAP_NET_RAW is bit 13 = 0x2000
        context = MockContext(
            file_contents={
                "/proc/2000/status": """Name:\tping
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000002000
CapEff:\t0000000000002000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/2000/comm": "ping\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/2000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "PROCESS CAPABILITIES AUDIT" in captured.out
        assert "PID" in captured.out
        assert "=" in captured.out or "-" in captured.out

    def test_multiple_high_risk_caps(self, capsys):
        """Process with multiple high-risk capabilities is detected."""
        from scripts.baremetal.process_capabilities_auditor import run

        # Multiple high-risk caps: DAC_OVERRIDE(1), SETGID(6), SETUID(7), NET_ADMIN(12), NET_RAW(13), SYS_ADMIN(21)
        # Hex: 0x2030C2
        context = MockContext(
            file_contents={
                "/proc/4000/status": """Name:\tsuspicious_app
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t00000000002030c2
CapEff:\t00000000002030c2
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
""",
                "/proc/4000/comm": "suspicious_app\n",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/4000"] if root == "/proc" else []
        )

        output = Output()
        result = run(["--format", "json"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)

        proc = data["processes"][0]
        assert proc["high_risk_count"] >= 4
        assert "CAP_SYS_ADMIN" in proc["high_risk_caps"]
        assert "CAP_NET_RAW" in proc["high_risk_caps"]
