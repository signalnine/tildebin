"""Tests for haproxy_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def haproxy_stats_healthy(fixtures_dir):
    """Load healthy HAProxy stats."""
    return (fixtures_dir / "services" / "haproxy_stats_healthy.csv").read_text()


@pytest.fixture
def haproxy_stats_backend_down(fixtures_dir):
    """Load HAProxy stats with backend down."""
    return (fixtures_dir / "services" / "haproxy_stats_backend_down.csv").read_text()


@pytest.fixture
def haproxy_stats_high_queue(fixtures_dir):
    """Load HAProxy stats with high queue."""
    return (fixtures_dir / "services" / "haproxy_stats_high_queue.csv").read_text()


class TestHaproxyHealth:
    """Tests for haproxy_health script."""

    def test_missing_socat_returns_error(self, mock_context):
        """Returns exit code 2 when socat not available."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = haproxy_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("socat" in e.lower() for e in output.errors)

    def test_socket_not_found_returns_error(self, mock_context):
        """Returns exit code 2 when socket not found."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(
            tools_available=["socat"],
            file_contents={},
        )
        output = Output()

        exit_code = haproxy_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("socket" in e.lower() for e in output.errors)

    def test_all_backends_healthy(self, mock_context, haproxy_stats_healthy):
        """Returns 0 when all backends are healthy."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(tools_available=["socat"])
        output = Output()

        # Use hidden --stats-data arg for testing
        exit_code = haproxy_health.run(["--stats-data", haproxy_stats_healthy], output, ctx)

        assert exit_code == 0
        assert output.data.get("healthy") is True
        assert output.data.get("backends_up") == 1
        assert output.data.get("backends_down") == 0
        assert output.data.get("servers_up") == 2
        assert output.data.get("servers_down") == 0

    def test_backend_down_returns_issue(self, mock_context, haproxy_stats_backend_down):
        """Returns 1 when a backend server is DOWN."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(tools_available=["socat"])
        output = Output()

        exit_code = haproxy_health.run(["--stats-data", haproxy_stats_backend_down], output, ctx)

        assert exit_code == 1
        assert output.data.get("healthy") is False
        assert output.data.get("servers_down") > 0
        assert len(output.data.get("issues", [])) > 0

    def test_high_queue_returns_warning(self, mock_context, haproxy_stats_high_queue):
        """Returns 0 but includes warning when queue is high."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(tools_available=["socat"])
        output = Output()

        exit_code = haproxy_health.run(["--stats-data", haproxy_stats_high_queue], output, ctx)

        # High queue generates warnings but not critical issues
        assert output.data.get("healthy") is True
        warnings = output.data.get("warnings", [])
        assert len(warnings) > 0
        assert any("queue" in w.lower() for w in warnings)

    def test_verbose_includes_details(self, mock_context, haproxy_stats_healthy):
        """--verbose includes frontend, backend, and server details."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(tools_available=["socat"])
        output = Output()

        exit_code = haproxy_health.run(["--verbose", "--stats-data", haproxy_stats_healthy], output, ctx)

        assert exit_code == 0
        assert "frontends" in output.data
        assert "backends" in output.data
        assert "servers" in output.data

    def test_custom_queue_threshold(self, mock_context, haproxy_stats_high_queue):
        """Custom --queue-crit threshold changes issue detection."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(tools_available=["socat"])
        output = Output()

        # Set critical threshold very high so queue doesn't trigger critical issue
        exit_code = haproxy_health.run(
            ["--queue-crit", "1000", "--stats-data", haproxy_stats_high_queue],
            output,
            ctx,
        )

        # Should still have warnings but no critical issues
        issues = output.data.get("issues", [])
        assert not any("critical" in i.lower() for i in issues)

    def test_explicit_socket_path(self, mock_context, haproxy_stats_healthy):
        """--socket allows specifying custom socket path."""
        from scripts.baremetal import haproxy_health

        ctx = mock_context(
            tools_available=["socat"],
            file_contents={
                "/custom/haproxy.sock": "",
            },
            command_outputs={
                ("socat", "-", "UNIX-CONNECT:/custom/haproxy.sock"): haproxy_stats_healthy,
            },
        )
        output = Output()

        exit_code = haproxy_health.run(["--socket", "/custom/haproxy.sock"], output, ctx)

        assert exit_code == 0
