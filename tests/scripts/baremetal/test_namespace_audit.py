"""Tests for namespace_audit script."""

import json
import pytest
from pathlib import Path

from boxctl.core.output import Output
from tests.conftest import MockContext, load_fixture


class TestNamespaceAudit:
    """Tests for namespace_audit."""

    def _build_root_ns_files(self) -> dict[str, str]:
        """Build mock files for init process namespaces."""
        return {
            "/proc/1/ns": "",  # Directory marker
            "/proc/1/ns/mnt": load_fixture("namespaces", "ns_mnt_root.txt"),
            "/proc/1/ns/pid": load_fixture("namespaces", "ns_pid_root.txt"),
            "/proc/1/ns/net": load_fixture("namespaces", "ns_net_root.txt"),
            "/proc/1/ns/ipc": load_fixture("namespaces", "ns_ipc_root.txt"),
            "/proc/1/ns/uts": load_fixture("namespaces", "ns_uts_root.txt"),
            "/proc/1/ns/user": load_fixture("namespaces", "ns_user_root.txt"),
            "/proc/1/ns/cgroup": load_fixture("namespaces", "ns_cgroup_root.txt"),
        }

    def test_healthy_namespaces(self, capsys):
        """All processes in root namespaces return exit code 0."""
        from scripts.baremetal.namespace_audit import run

        files = self._build_root_ns_files()
        # Add a process that shares all namespaces with init
        files.update({
            "/proc/100": "",  # Directory marker for glob
            "/proc/100/ns/mnt": load_fixture("namespaces", "ns_mnt_root.txt"),
            "/proc/100/ns/pid": load_fixture("namespaces", "ns_pid_root.txt"),
            "/proc/100/ns/net": load_fixture("namespaces", "ns_net_root.txt"),
            "/proc/100/ns/ipc": load_fixture("namespaces", "ns_ipc_root.txt"),
            "/proc/100/ns/uts": load_fixture("namespaces", "ns_uts_root.txt"),
            "/proc/100/ns/user": load_fixture("namespaces", "ns_user_root.txt"),
            "/proc/100/ns/cgroup": load_fixture("namespaces", "ns_cgroup_root.txt"),
            "/proc/100/comm": load_fixture("namespaces", "proc_comm.txt"),
            "/proc/100/status": load_fixture("namespaces", "proc_status.txt"),
        })

        context = MockContext(file_contents=files)
        # Override glob to return PIDs
        context.glob = lambda pattern, root=".": ["/proc/1", "/proc/100"] if pattern == "[0-9]*" else []

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "Namespace" in captured.out

    def test_container_isolated_process(self, capsys):
        """Process in isolated namespace is detected."""
        from scripts.baremetal.namespace_audit import run

        files = self._build_root_ns_files()
        # Add a containerized process with different net namespace
        files.update({
            "/proc/500": "",
            "/proc/500/ns/mnt": load_fixture("namespaces", "ns_mnt_root.txt"),
            "/proc/500/ns/pid": load_fixture("namespaces", "ns_pid_root.txt"),
            "/proc/500/ns/net": load_fixture("namespaces", "ns_net_container.txt"),  # Different!
            "/proc/500/ns/ipc": load_fixture("namespaces", "ns_ipc_root.txt"),
            "/proc/500/ns/uts": load_fixture("namespaces", "ns_uts_root.txt"),
            "/proc/500/ns/user": load_fixture("namespaces", "ns_user_root.txt"),
            "/proc/500/ns/cgroup": load_fixture("namespaces", "ns_cgroup_root.txt"),
            "/proc/500/comm": "nginx\n",
            "/proc/500/status": load_fixture("namespaces", "proc_status.txt"),
        })

        context = MockContext(file_contents=files)
        context.glob = lambda pattern, root=".": ["/proc/1", "/proc/500"] if pattern == "[0-9]*" else []

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Check that isolated process is counted
        stats = data["audit_results"]["statistics"]["namespaces"]["net"]
        assert stats["processes_isolated"] > 0

    def test_partial_isolation_warning(self, capsys):
        """Process with partial isolation (net but not mnt) triggers warning."""
        from scripts.baremetal.namespace_audit import run

        files = self._build_root_ns_files()
        # Add a process with net isolated but mnt shared (partial isolation)
        files.update({
            "/proc/600": "",
            "/proc/600/ns/mnt": load_fixture("namespaces", "ns_mnt_root.txt"),  # Root
            "/proc/600/ns/pid": load_fixture("namespaces", "ns_pid_root.txt"),
            "/proc/600/ns/net": load_fixture("namespaces", "ns_net_container.txt"),  # Isolated
            "/proc/600/ns/ipc": load_fixture("namespaces", "ns_ipc_root.txt"),
            "/proc/600/ns/uts": load_fixture("namespaces", "ns_uts_root.txt"),
            "/proc/600/ns/user": load_fixture("namespaces", "ns_user_root.txt"),
            "/proc/600/ns/cgroup": load_fixture("namespaces", "ns_cgroup_root.txt"),
            "/proc/600/comm": "weird_proc\n",
            "/proc/600/status": load_fixture("namespaces", "proc_status.txt"),
        })

        context = MockContext(file_contents=files)
        context.glob = lambda pattern, root=".": ["/proc/1", "/proc/600"] if pattern == "[0-9]*" else []

        output = Output()
        result = run([], output, context)

        assert result == 1  # Warning triggers exit code 1
        captured = capsys.readouterr()
        assert "partial" in captured.out.lower() or "isolated" in captured.out.lower()

    def test_json_output(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.namespace_audit import run

        files = self._build_root_ns_files()
        context = MockContext(file_contents=files)
        context.glob = lambda pattern, root=".": ["/proc/1"] if pattern == "[0-9]*" else []

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "timestamp" in data
        assert "audit_results" in data
        assert "statistics" in data["audit_results"]
        assert "issues" in data["audit_results"]

    def test_filter_namespace_types(self, capsys):
        """Namespace type filter works correctly."""
        from scripts.baremetal.namespace_audit import run

        files = self._build_root_ns_files()
        context = MockContext(file_contents=files)
        context.glob = lambda pattern, root=".": ["/proc/1"] if pattern == "[0-9]*" else []

        output = Output()
        result = run(["--types", "pid,net", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Only pid and net should be audited
        ns_keys = list(data["audit_results"]["statistics"]["namespaces"].keys())
        assert "pid" in ns_keys
        assert "net" in ns_keys
        assert "mnt" not in ns_keys

    def test_invalid_namespace_type_exit_2(self, capsys):
        """Invalid namespace type returns exit code 2."""
        from scripts.baremetal.namespace_audit import run

        files = self._build_root_ns_files()
        context = MockContext(file_contents=files)

        output = Output()
        result = run(["--types", "invalid_ns"], output, context)

        assert result == 2
        assert output.errors

    def test_missing_proc_exit_2(self, capsys):
        """Missing /proc filesystem returns exit code 2."""
        from scripts.baremetal.namespace_audit import run

        context = MockContext(file_contents={})
        output = Output()

        result = run([], output, context)

        assert result == 2
        assert output.errors
