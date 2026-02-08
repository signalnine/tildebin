"""Tests for iptables_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestIptablesAudit:
    """Tests for iptables_audit."""

    def test_healthy_rules(self, capsys):
        """Healthy rules return exit code 0."""
        from scripts.baremetal.iptables_audit import run

        context = MockContext(
            tools_available=["iptables"],
            command_outputs={
                ("iptables", "-t", "filter", "-L", "-v", "-n", "--line-numbers"): load_fixture(
                    "iptables_healthy.txt"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert output.data.get("has_warnings") is False
        assert "stats" in output.data
        assert output.data["stats"]["total_rules"] >= 0

    def test_high_rules_warning(self, capsys):
        """High rule count triggers warning."""
        from scripts.baremetal.iptables_audit import run

        context = MockContext(
            tools_available=["iptables"],
            command_outputs={
                ("iptables", "-t", "filter", "-L", "-v", "-n", "--line-numbers"): load_fixture(
                    "iptables_high_rules.txt"
                ),
            },
        )
        output = Output()

        # Lower threshold to trigger warning
        result = run(["--max-rules", "5"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_accept_all_warning(self, capsys):
        """Accept all rule triggers warning."""
        from scripts.baremetal.iptables_audit import run

        context = MockContext(
            tools_available=["iptables"],
            command_outputs={
                ("iptables", "-t", "filter", "-L", "-v", "-n", "--line-numbers"): load_fixture(
                    "iptables_accept_all.txt"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "ACCEPT" in captured.out or "accepts ALL" in captured.out

    def test_empty_chain_warning(self, capsys):
        """Empty unreferenced chain triggers warning."""
        from scripts.baremetal.iptables_audit import run

        context = MockContext(
            tools_available=["iptables"],
            command_outputs={
                ("iptables", "-t", "filter", "-L", "-v", "-n", "--line-numbers"): load_fixture(
                    "iptables_empty_chain.txt"
                ),
            },
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "empty" in captured.out.lower() or "CUSTOM_CHAIN" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.iptables_audit import run

        context = MockContext(
            tools_available=["iptables"],
            command_outputs={
                ("iptables", "-t", "filter", "-L", "-v", "-n", "--line-numbers"): load_fixture(
                    "iptables_healthy.txt"
                ),
            },
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "stats" in data
        assert "total_rules" in data["stats"]
        assert "issues" in data
        assert "table" in data

    def test_missing_iptables_exit_2(self, capsys):
        """Missing iptables returns exit code 2."""
        from scripts.baremetal.iptables_audit import run

        context = MockContext(tools_available=[])
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_invalid_max_rules_exit_2(self, capsys):
        """Invalid --max-rules returns exit code 2."""
        from scripts.baremetal.iptables_audit import run

        context = MockContext(tools_available=["iptables"])
        output = Output()

        result = run(["--max-rules", "0"], output, context)

        assert result == 2
