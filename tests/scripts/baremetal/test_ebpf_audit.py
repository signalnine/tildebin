"""Tests for ebpf_audit script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


def _make_programs(count, prog_type="cgroup_skb"):
    """Generate a list of BPF program dicts."""
    return json.dumps([
        {"id": i, "type": prog_type, "name": f"prog{i}", "tag": f"tag{i}"}
        for i in range(1, count + 1)
    ])


def _make_maps(entries):
    """Generate a list of BPF map dicts.

    Args:
        entries: list of (name, bytes_memlock) tuples
    """
    return json.dumps([
        {"id": i + 1, "type": "hash", "name": name, "bytes_memlock": memlock}
        for i, (name, memlock) in enumerate(entries)
    ])


class TestEbpfAudit:
    """Tests for ebpf_audit."""

    def test_bpftool_missing(self, mock_context):
        """Returns exit code 2 when bpftool not available."""
        from scripts.baremetal import ebpf_audit

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = ebpf_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("bpftool" in e.lower() for e in output.errors)

    def test_no_programs(self, mock_context):
        """Empty arrays return exit code 0."""
        from scripts.baremetal import ebpf_audit

        ctx = mock_context(
            tools_available=["bpftool"],
            command_outputs={
                ("bpftool", "prog", "list", "--json"): "[]",
                ("bpftool", "map", "list", "--json"): "[]",
            },
        )
        output = Output()

        exit_code = ebpf_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["program_count"] == 0
        assert output.data["map_count"] == 0

    def test_healthy_programs(self, mock_context):
        """Few programs and small maps return exit code 0."""
        from scripts.baremetal import ebpf_audit

        progs = _make_programs(5)
        maps = _make_maps([("map1", 4096), ("map2", 8192)])

        ctx = mock_context(
            tools_available=["bpftool"],
            command_outputs={
                ("bpftool", "prog", "list", "--json"): progs,
                ("bpftool", "map", "list", "--json"): maps,
            },
        )
        output = Output()

        exit_code = ebpf_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["program_count"] == 5
        assert output.data["map_count"] == 2
        assert output.data["status"] == "healthy"

    def test_excessive_programs(self, mock_context):
        """More than 100 programs triggers WARNING and exit code 1."""
        from scripts.baremetal import ebpf_audit

        progs = _make_programs(105)
        maps = _make_maps([("map1", 4096)])

        ctx = mock_context(
            tools_available=["bpftool"],
            command_outputs={
                ("bpftool", "prog", "list", "--json"): progs,
                ("bpftool", "map", "list", "--json"): maps,
            },
        )
        output = Output()

        exit_code = ebpf_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "warning"
        warnings = [i for i in output.data["issues"] if i["severity"] == "WARNING"]
        assert any("Excessive" in w["message"] for w in warnings)

    def test_large_maps(self, mock_context):
        """Map with bytes_memlock > 1GB triggers WARNING and exit code 1."""
        from scripts.baremetal import ebpf_audit

        progs = _make_programs(3)
        # 2 GB map
        large_memlock = 2 * 1024 * 1024 * 1024
        maps = _make_maps([("small_map", 4096), ("huge_map", large_memlock)])

        ctx = mock_context(
            tools_available=["bpftool"],
            command_outputs={
                ("bpftool", "prog", "list", "--json"): progs,
                ("bpftool", "map", "list", "--json"): maps,
            },
        )
        output = Output()

        exit_code = ebpf_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["status"] == "warning"
        warnings = [i for i in output.data["issues"] if i["severity"] == "WARNING"]
        assert any("Large BPF map" in w["message"] for w in warnings)
        assert any("huge_map" in w["message"] for w in warnings)

    def test_json_output(self, mock_context, capsys):
        """Verify programs and maps lists appear in JSON output data."""
        from scripts.baremetal import ebpf_audit

        progs = _make_programs(3)
        maps = _make_maps([("map1", 4096), ("map2", 8192)])

        ctx = mock_context(
            tools_available=["bpftool"],
            command_outputs={
                ("bpftool", "prog", "list", "--json"): progs,
                ("bpftool", "map", "list", "--json"): maps,
            },
        )
        output = Output()

        exit_code = ebpf_audit.run(["--format", "json"], output, ctx)

        assert exit_code == 0

        # Check structured output data
        assert "programs" in output.data
        assert "maps" in output.data
        assert len(output.data["programs"]) == 3
        assert len(output.data["maps"]) == 2

        # Verify JSON was printed
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "program_count" in data
        assert "map_count" in data
        assert data["program_count"] == 3
        assert data["map_count"] == 2
