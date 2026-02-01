"""Tests for conntrack_monitor script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_fixture(name: str) -> str:
    """Load a fixture file."""
    return (FIXTURES_DIR / name).read_text()


class TestConntrackMonitor:
    """Tests for conntrack_monitor."""

    def test_healthy_usage(self, capsys):
        """Healthy conntrack usage returns exit code 0."""
        from scripts.baremetal.conntrack_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/netfilter/nf_conntrack_count": load_fixture(
                    "conntrack_healthy.txt"
                ),
                "/proc/sys/net/netfilter/nf_conntrack_max": load_fixture(
                    "conntrack_max_healthy.txt"
                ),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "healthy" in captured.out.lower()

    def test_high_usage_warning(self, capsys):
        """High usage triggers warning."""
        from scripts.baremetal.conntrack_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/netfilter/nf_conntrack_count": load_fixture(
                    "conntrack_high_usage.txt"
                ),
                "/proc/sys/net/netfilter/nf_conntrack_max": load_fixture(
                    "conntrack_max_healthy.txt"
                ),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_critical_usage(self, capsys):
        """Critical usage triggers critical alert."""
        from scripts.baremetal.conntrack_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/netfilter/nf_conntrack_count": load_fixture(
                    "conntrack_critical_usage.txt"
                ),
                "/proc/sys/net/netfilter/nf_conntrack_max": load_fixture(
                    "conntrack_max_healthy.txt"
                ),
            }
        )
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.conntrack_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/netfilter/nf_conntrack_count": load_fixture(
                    "conntrack_healthy.txt"
                ),
                "/proc/sys/net/netfilter/nf_conntrack_max": load_fixture(
                    "conntrack_max_healthy.txt"
                ),
            }
        )
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "conntrack" in data
        assert "count" in data["conntrack"]
        assert "max" in data["conntrack"]
        assert "usage_percent" in data["conntrack"]
        assert "issues" in data

    def test_custom_thresholds(self, capsys):
        """Custom thresholds work correctly."""
        from scripts.baremetal.conntrack_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/netfilter/nf_conntrack_count": load_fixture(
                    "conntrack_healthy.txt"
                ),
                "/proc/sys/net/netfilter/nf_conntrack_max": load_fixture(
                    "conntrack_max_healthy.txt"
                ),
            }
        )
        output = Output()

        # With very low thresholds, even healthy usage should warn
        result = run(["--warn", "1", "--crit", "2"], output, context)

        assert result == 1  # 1000/65536 = 1.5% > 1%

    def test_missing_conntrack_exit_2(self, capsys):
        """Missing conntrack files returns exit code 2."""
        from scripts.baremetal.conntrack_monitor import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2

    def test_invalid_thresholds_exit_2(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.conntrack_monitor import run

        context = MockContext(
            file_contents={
                "/proc/sys/net/netfilter/nf_conntrack_count": "1000\n",
                "/proc/sys/net/netfilter/nf_conntrack_max": "65536\n",
            }
        )
        output = Output()

        # warn >= crit is invalid
        result = run(["--warn", "90", "--crit", "75"], output, context)

        assert result == 2
