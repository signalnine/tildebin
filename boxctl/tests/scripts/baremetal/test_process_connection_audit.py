"""Tests for process_connection_audit script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestProcessConnectionAudit:
    """Tests for process_connection_audit."""

    def test_no_connections_returns_zero(self, capsys):
        """No connections returns exit code 0."""
        from scripts.baremetal.process_connection_audit import run

        # Only listening sockets, no active connections
        context = MockContext(
            file_contents={
                "/proc/net/tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
""",
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run([], output, context)

        assert result == 0
        captured = capsys.readouterr()
        assert "0" in captured.out or "No" in captured.out or "OK" in captured.out

    def test_established_connections_parsed(self, capsys):
        """ESTABLISHED connections are parsed correctly."""
        from scripts.baremetal.process_connection_audit import run

        # State 01 = ESTABLISHED
        context = MockContext(
            file_contents={
                "/proc/net/tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:0CEA 01 00000000:00000000 02:00000A0D 00000000  1000        0 23456 2 0000000000000000 20 4 0 10 -1
""",
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--format", "json"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["summary"]["total_connections"] == 1
        assert data["summary"]["established"] == 1

    def test_excessive_connections_triggers_warning(self, capsys):
        """Process with excessive connections triggers warning."""
        from scripts.baremetal.process_connection_audit import run

        # Generate 5 connections with same inode (same process)
        tcp_lines = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
"""
        for i in range(5):
            port = 53746 + i
            tcp_lines += f"   {i}: C0A80A0A:8080 C0A80A01:{port:04X} 01 00000000:00000000 02:00000A0D 00000000  1000        0 20001 2 0000000000000000 20 4 0 10 -1\n"

        context = MockContext(
            file_contents={
                "/proc/net/tcp": tcp_lines,
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
                "/proc/1000/comm": "nginx\n",
                "/proc/1000/cmdline": "nginx\x00-g\x00daemon off\x00",
                "/proc/1000/fd/3": "socket:[20001]",
            }
        )
        context.glob = lambda pattern, root="/": (
            ["/proc/1000"] if root == "/proc" and pattern == "[0-9]*" else
            ["/proc/1000/fd/3"] if "/fd" in root else []
        )

        output = Output()
        # Set threshold low to trigger warning
        result = run(["--max-per-process", "3", "--format", "json"], output, context)

        assert result == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["has_issues"] is True
        assert len(data["issues"]) > 0

    def test_json_output_structure(self, capsys):
        """JSON output contains expected fields."""
        from scripts.baremetal.process_connection_audit import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:0CEA 01 00000000:00000000 02:00000A0D 00000000  1000        0 23456 2 0000000000000000 20 4 0 10 -1
""",
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "process_summary" in data
        assert "state_counts" in data
        assert "issues" in data
        assert "summary" in data
        assert "has_issues" in data

    def test_warn_only_silent_when_no_issues(self, capsys):
        """Warn-only mode produces no output when no issues."""
        from scripts.baremetal.process_connection_audit import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:0CEA 01 00000000:00000000 02:00000A0D 00000000  1000        0 23456 2 0000000000000000 20 4 0 10 -1
""",
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--warn-only"], output, context)

        assert result == 0
        captured = capsys.readouterr()
        # Might still have some output but no issues reported
        assert "WARNING" not in captured.out

    def test_state_filter(self, capsys):
        """State filter shows only specified state."""
        from scripts.baremetal.process_connection_audit import run

        # Mix of ESTABLISHED (01) and TIME_WAIT (06)
        context = MockContext(
            file_contents={
                "/proc/net/tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:0CEA 01 00000000:00000000 02:00000A0D 00000000  1000        0 23456 2 0000000000000000 20 4 0 10 -1
   1: 0100007F:1F91 0100007F:0CEB 06 00000000:00000000 02:00000A0D 00000000  1000        0 23457 2 0000000000000000 20 4 0 10 -1
""",
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--state", "TIME_WAIT", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["summary"]["total_connections"] == 1
        assert data["summary"]["time_wait"] == 1

    def test_exclude_loopback(self, capsys):
        """Exclude-loopback filters localhost connections."""
        from scripts.baremetal.process_connection_audit import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:0CEA 01 00000000:00000000 02:00000A0D 00000000  1000        0 23456 2 0000000000000000 20 4 0 10 -1
   1: C0A80A0A:1F90 C0A80A01:0CEA 01 00000000:00000000 02:00000A0D 00000000  1000        0 23457 2 0000000000000000 20 4 0 10 -1
""",
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--exclude-loopback", "--format", "json"], output, context)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        # Should only have the non-loopback connection
        assert data["summary"]["total_connections"] == 1

    def test_table_format(self, capsys):
        """Table format produces formatted output."""
        from scripts.baremetal.process_connection_audit import run

        context = MockContext(
            file_contents={
                "/proc/net/tcp": """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:0CEA 01 00000000:00000000 02:00000A0D 00000000  1000        0 23456 2 0000000000000000 20 4 0 10 -1
""",
                "/proc/net/tcp6": """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
""",
            }
        )
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run(["--format", "table"], output, context)

        captured = capsys.readouterr()
        assert "PID" in captured.out
        assert "-" in captured.out

    def test_missing_proc_net_returns_two(self, capsys):
        """Missing /proc/net/tcp returns exit code 2."""
        from scripts.baremetal.process_connection_audit import run

        context = MockContext(file_contents={})
        context.glob = lambda pattern, root="/": []

        output = Output()
        result = run([], output, context)

        assert result == 2
