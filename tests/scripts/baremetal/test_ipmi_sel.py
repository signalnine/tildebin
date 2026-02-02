#!/usr/bin/env python3
"""Tests for scripts/baremetal/ipmi_sel.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.ipmi_sel import (
    run,
    categorize_event_severity,
    parse_sel_entry
)


class TestIpmiSel:
    """Tests for ipmi_sel script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = Context()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_categorize_critical_failure(self):
        """Test categorizing failure events as critical."""
        assert categorize_event_severity("Power Supply Failure", "") == "critical"
        assert categorize_event_severity("Uncorrectable Error", "") == "critical"
        assert categorize_event_severity("Hardware failure detected", "") == "critical"

    def test_categorize_critical_fatal(self):
        """Test categorizing fatal events as critical."""
        assert categorize_event_severity("Fatal error", "") == "critical"
        assert categorize_event_severity("Non-recoverable error", "") == "critical"

    def test_categorize_warning_ecc(self):
        """Test categorizing ECC events as warning."""
        assert categorize_event_severity("Correctable ECC error", "") == "warning"
        assert categorize_event_severity("Memory ECC event", "") == "warning"

    def test_categorize_warning_threshold(self):
        """Test categorizing threshold events as warning."""
        assert categorize_event_severity("Upper Critical threshold", "") == "warning"
        assert categorize_event_severity("Temperature threshold exceeded", "") == "warning"

    def test_categorize_info_deasserted(self):
        """Test categorizing deasserted events as info."""
        assert categorize_event_severity("Normal event", "Deasserted") == "info"
        assert categorize_event_severity("Status", "OK") == "info"

    def test_parse_sel_entry_valid(self):
        """Test parsing valid SEL entry."""
        line = "1 | 01/15/2025 | 14:23:45 | Memory | Correctable ECC | Asserted"
        entry = parse_sel_entry(line)

        assert entry is not None
        assert entry['id'] == '1'
        assert entry['date'] == '01/15/2025'
        assert entry['time'] == '14:23:45'
        assert entry['sensor'] == 'Memory'
        assert entry['event'] == 'Correctable ECC'
        assert entry['status'] == 'Asserted'
        assert entry['severity'] == 'warning'

    def test_parse_sel_entry_empty(self):
        """Test parsing empty line returns None."""
        assert parse_sel_entry("") is None
        assert parse_sel_entry("   ") is None

    def test_parse_sel_entry_short(self):
        """Test parsing line with too few fields returns None."""
        assert parse_sel_entry("1 | 01/15/2025") is None

    def test_format_json(self):
        """Test JSON output format."""
        output = Output()
        output.emit({
            "entries": [{
                "id": "1",
                "date": "01/15/2025",
                "time": "14:23:45",
                "sensor": "Memory",
                "event": "Correctable ECC",
                "status": "Asserted",
                "severity": "warning"
            }],
            "summary": {
                "total": 1,
                "critical": 0,
                "warning": 1,
                "info": 0
            }
        })

        data = output.get_data()
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "entries" in parsed
        assert "summary" in parsed
        assert parsed["summary"]["warning"] == 1
