"""Tests for packet_drop_analyzer script."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from boxctl.core.output import Output
from tests.conftest import MockContext


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "net"


def load_json_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    return json.loads((FIXTURES_DIR / name).read_text())


class MockContextWithStats(MockContext):
    """MockContext that supports interface statistics."""

    def __init__(self, stats_data: dict, **kwargs):
        super().__init__(**kwargs)
        self.stats_data = stats_data
        self._stats_calls = 0

    def file_exists(self, path: str) -> bool:
        """Check if path exists in mocked data."""
        if path == "/sys/class/net":
            return True
        for iface in self.stats_data:
            if path == f"/sys/class/net/{iface}":
                return True
            if path == f"/sys/class/net/{iface}/statistics":
                return True
            if path.startswith(f"/sys/class/net/{iface}/statistics/"):
                return True
            if path == f"/sys/class/net/{iface}/operstate":
                return True
        return False

    def read_file(self, path: str) -> str:
        """Read mocked file content."""
        for iface, stats in self.stats_data.items():
            if path == f"/sys/class/net/{iface}/operstate":
                return stats.get("operstate", "up")
            for stat_name in stats:
                if path == f"/sys/class/net/{iface}/statistics/{stat_name}":
                    return str(stats[stat_name])
        raise FileNotFoundError(f"No mock content for: {path}")

    def glob(self, pattern: str, root: str = ".") -> list[str]:
        """Return mocked glob results for interfaces."""
        if root == "/sys/class/net":
            return [f"/sys/class/net/{iface}" for iface in self.stats_data]
        return []


class TestPacketDropAnalyzer:
    """Tests for packet_drop_analyzer."""

    def test_healthy_interface(self, capsys):
        """Healthy interface with no drops returns exit code 0."""
        from scripts.baremetal.packet_drop_analyzer import run

        stats_data = load_json_fixture("iface_stats_healthy.json")
        context = MockContextWithStats(stats_data)
        output = Output()

        with patch("time.sleep"):
            result = run(["--interval", "0.01"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out or "eth0" in captured.out

    def test_drops_warning(self, capsys):
        """Interface with drops above warning threshold returns exit code 1."""
        from scripts.baremetal.packet_drop_analyzer import run

        # Create stats with increasing drops between samples
        stats_before = load_json_fixture("iface_stats_healthy.json")
        stats_after = load_json_fixture("iface_stats_drops.json")

        class MockContextWithIncreasing(MockContextWithStats):
            def __init__(self):
                super().__init__(stats_before)
                self.call_count = 0

            def read_file(self, path: str) -> str:
                # Switch to after stats on second read
                stats = stats_after if self.call_count > 10 else stats_before
                self.call_count += 1
                for iface, iface_stats in stats.items():
                    if path == f"/sys/class/net/{iface}/operstate":
                        return iface_stats.get("operstate", "up")
                    for stat_name in iface_stats:
                        if path == f"/sys/class/net/{iface}/statistics/{stat_name}":
                            return str(iface_stats[stat_name])
                raise FileNotFoundError(f"No mock content for: {path}")

        context = MockContextWithIncreasing()
        output = Output()

        with patch("time.sleep"):
            # Use low threshold to trigger warning
            result = run(["--interval", "1", "--warn", "0.1", "--crit", "100"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "CRIT" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.packet_drop_analyzer import run

        stats_data = load_json_fixture("iface_stats_healthy.json")
        context = MockContextWithStats(stats_data)
        output = Output()

        with patch("time.sleep"):
            result = run(["--format", "json", "--interval", "0.01"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "interfaces" in data
        assert "issues" in data
        assert "summary" in data
        assert "sample_interval_sec" in data

    def test_specific_interface(self, capsys):
        """Checking specific interface works."""
        from scripts.baremetal.packet_drop_analyzer import run

        stats_data = load_json_fixture("iface_stats_healthy.json")
        context = MockContextWithStats(stats_data)
        output = Output()

        with patch("time.sleep"):
            result = run(["--interface", "eth0", "--interval", "0.01"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "eth0" in captured.out

    def test_missing_interface_exit_2(self, capsys):
        """Missing interface returns exit code 2."""
        from scripts.baremetal.packet_drop_analyzer import run

        stats_data = load_json_fixture("iface_stats_healthy.json")
        context = MockContextWithStats(stats_data)
        output = Output()

        result = run(["--interface", "nonexistent"], output, context)

        assert result == 2

    def test_invalid_interval_exit_2(self, capsys):
        """Invalid interval returns exit code 2."""
        from scripts.baremetal.packet_drop_analyzer import run

        stats_data = load_json_fixture("iface_stats_healthy.json")
        context = MockContextWithStats(stats_data)
        output = Output()

        result = run(["--interval", "0"], output, context)

        assert result == 2

    def test_invalid_thresholds_exit_2(self, capsys):
        """Invalid thresholds return exit code 2."""
        from scripts.baremetal.packet_drop_analyzer import run

        stats_data = load_json_fixture("iface_stats_healthy.json")
        context = MockContextWithStats(stats_data)
        output = Output()

        # warn >= crit is invalid
        result = run(["--warn", "10", "--crit", "5"], output, context)

        assert result == 2
