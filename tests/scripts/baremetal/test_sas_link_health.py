"""Tests for sas_link_health script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


def _make_phy_files(phy_name, negotiated, maximum,
                    invalid_dword=0, loss_of_sync=0,
                    disparity_error=0, reset_problem=0):
    """Helper to create sysfs file_contents for a SAS PHY."""
    base = f"/sys/class/sas_phy/{phy_name}"
    return {
        f"{base}/negotiated_linkrate": f"{negotiated}\n",
        f"{base}/maximum_linkrate": f"{maximum}\n",
        f"{base}/invalid_dword_count": f"{invalid_dword}\n",
        f"{base}/loss_of_dword_sync_count": f"{loss_of_sync}\n",
        f"{base}/running_disparity_error_count": f"{disparity_error}\n",
        f"{base}/phy_reset_problem_count": f"{reset_problem}\n",
    }


class TestSasLinkHealth:
    """Tests for sas_link_health."""

    def test_no_sas_phys(self, capsys):
        """No /sys/class/sas_phy/ entries returns exit 0 with INFO."""
        from scripts.baremetal.sas_link_health import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 0
        assert "No SAS hardware" in output.summary

    def test_healthy_links(self, capsys):
        """Negotiated equals maximum with zero errors returns exit 0."""
        from scripts.baremetal.sas_link_health import run

        files = _make_phy_files("phy-0:0", "12.0 Gbit", "12.0 Gbit")
        context = MockContext(file_contents=files)
        output = Output()

        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out
        assert "12.0 Gbit" in captured.out

    def test_speed_downgrade(self, capsys):
        """Negotiated 6.0 Gbit vs maximum 12.0 Gbit returns exit 1 WARNING."""
        from scripts.baremetal.sas_link_health import run

        files = _make_phy_files("phy-0:0", "6.0 Gbit", "12.0 Gbit")
        context = MockContext(file_contents=files)
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "6.0 Gbit" in captured.out
        assert "12.0 Gbit" in captured.out

    def test_link_errors(self, capsys):
        """Non-zero invalid_dword_count returns exit 1 WARNING."""
        from scripts.baremetal.sas_link_health import run

        files = _make_phy_files("phy-0:0", "12.0 Gbit", "12.0 Gbit",
                                invalid_dword=5)
        context = MockContext(file_contents=files)
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "invalid dword count" in captured.out
        assert "5" in captured.out

    def test_multiple_error_types(self, capsys):
        """Several error counters non-zero returns exit 1 with multiple issues."""
        from scripts.baremetal.sas_link_health import run

        files = _make_phy_files("phy-0:0", "12.0 Gbit", "12.0 Gbit",
                                invalid_dword=3, loss_of_sync=7,
                                disparity_error=2)
        context = MockContext(file_contents=files)
        output = Output()

        result = run([], output, context)

        assert result == 1
        captured = capsys.readouterr()
        assert "invalid dword count" in captured.out
        assert "loss of dword sync count" in captured.out
        assert "running disparity error count" in captured.out

    def test_json_output(self, capsys):
        """JSON output contains PHY data structure."""
        from scripts.baremetal.sas_link_health import run

        files = _make_phy_files("phy-0:0", "12.0 Gbit", "12.0 Gbit")
        context = MockContext(file_contents=files)
        output = Output()

        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "phys" in data
        assert "summary" in data
        assert "issues" in data
        assert "healthy" in data
        assert len(data["phys"]) == 1
        phy = data["phys"][0]
        assert phy["phy"] == "phy-0:0"
        assert phy["negotiated_linkrate"] == "12.0 Gbit"
        assert phy["maximum_linkrate"] == "12.0 Gbit"
        assert "invalid_dword_count" in phy
        assert "loss_of_dword_sync_count" in phy
        assert "running_disparity_error_count" in phy
        assert "phy_reset_problem_count" in phy
