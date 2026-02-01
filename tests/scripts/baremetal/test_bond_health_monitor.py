"""Tests for bond_health_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestBondHealthMonitor:
    """Tests for bond_health_monitor."""

    def test_bonding_not_available(self):
        """Returns exit code 2 when bonding not available."""
        from scripts.baremetal.bond_health_monitor import run

        ctx = MockContext(file_contents={})
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert any("bonding" in e.lower() for e in output.errors)

    def test_healthy_bond(self, capsys):
        """Returns 0 when bond is healthy."""
        from scripts.baremetal.bond_health_monitor import run

        content = load_fixture("proc_bonding_healthy.txt")
        ctx = MockContext(
            file_contents={
                "/proc/net/bonding": "",  # exists marker
                "/proc/net/bonding/bond0": content,
            }
        )
        ctx.glob = lambda p, r: ["/proc/net/bonding/bond0"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        bonds = output.data.get("bonds", [])
        assert len(bonds) == 1
        assert len(bonds[0]["errors"]) == 0
        assert len(bonds[0]["warnings"]) == 0

    def test_degraded_bond_warning(self, capsys):
        """Returns 1 when bond has degraded slave."""
        from scripts.baremetal.bond_health_monitor import run

        content = load_fixture("proc_bonding_degraded.txt")
        ctx = MockContext(
            file_contents={
                "/proc/net/bonding": "",
                "/proc/net/bonding/bond0": content,
            }
        )
        ctx.glob = lambda p, r: ["/proc/net/bonding/bond0"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        bonds = output.data.get("bonds", [])
        assert len(bonds[0]["warnings"]) > 0
        # Should detect down slave
        assert any("eth1" in w and "down" in w for w in bonds[0]["warnings"])

    def test_speed_mismatch_warning(self, capsys):
        """Detects speed mismatch between slaves."""
        from scripts.baremetal.bond_health_monitor import run

        content = load_fixture("proc_bonding_speed_mismatch.txt")
        ctx = MockContext(
            file_contents={
                "/proc/net/bonding": "",
                "/proc/net/bonding/bond0": content,
            }
        )
        ctx.glob = lambda p, r: ["/proc/net/bonding/bond0"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        bonds = output.data.get("bonds", [])
        assert any("speed" in w.lower() for w in bonds[0]["warnings"])

    def test_no_slaves_error(self, capsys):
        """Detects bond with no slaves as error."""
        from scripts.baremetal.bond_health_monitor import run

        content = load_fixture("proc_bonding_no_slaves.txt")
        ctx = MockContext(
            file_contents={
                "/proc/net/bonding": "",
                "/proc/net/bonding/bond0": content,
            }
        )
        ctx.glob = lambda p, r: ["/proc/net/bonding/bond0"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        bonds = output.data.get("bonds", [])
        assert len(bonds[0]["errors"]) > 0
        assert any("no slave" in e.lower() for e in bonds[0]["errors"])

    def test_active_backup_mode(self, capsys):
        """Parses active-backup mode correctly."""
        from scripts.baremetal.bond_health_monitor import run

        content = load_fixture("proc_bonding_active_backup.txt")
        ctx = MockContext(
            file_contents={
                "/proc/net/bonding": "",
                "/proc/net/bonding/bond0": content,
            }
        )
        ctx.glob = lambda p, r: ["/proc/net/bonding/bond0"]
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        bonds = output.data.get("bonds", [])
        assert "active-backup" in bonds[0]["mode"]
        assert bonds[0]["active_slave"] == "eth0"
        assert bonds[0]["primary"] == "eth0"

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.bond_health_monitor import run

        content = load_fixture("proc_bonding_healthy.txt")
        ctx = MockContext(
            file_contents={
                "/proc/net/bonding": "",
                "/proc/net/bonding/bond0": content,
            }
        )
        ctx.glob = lambda p, r: ["/proc/net/bonding/bond0"]
        output = Output()

        exit_code = run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert "name" in data[0]
        assert "mode" in data[0]
        assert "slaves" in data[0]

    def test_specific_bond_check(self, capsys):
        """Can check specific bond with -b option."""
        from scripts.baremetal.bond_health_monitor import run

        content = load_fixture("proc_bonding_healthy.txt")
        ctx = MockContext(
            file_contents={
                "/proc/net/bonding": "",
                "/proc/net/bonding/bond0": content,
            }
        )
        output = Output()

        exit_code = run(["-b", "bond0"], output, ctx)

        assert exit_code == 0
        bonds = output.data.get("bonds", [])
        assert len(bonds) == 1
        assert bonds[0]["name"] == "bond0"
