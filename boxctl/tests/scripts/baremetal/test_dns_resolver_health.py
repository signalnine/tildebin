"""Tests for dns_resolver_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def resolv_conf_healthy(fixtures_dir):
    """Load healthy resolv.conf."""
    return (fixtures_dir / "services" / "resolv_conf_healthy.txt").read_text()


@pytest.fixture
def resolv_conf_empty(fixtures_dir):
    """Load empty resolv.conf."""
    return (fixtures_dir / "services" / "resolv_conf_empty.txt").read_text()


@pytest.fixture
def resolv_conf_loopback(fixtures_dir):
    """Load loopback resolv.conf."""
    return (fixtures_dir / "services" / "resolv_conf_loopback.txt").read_text()


@pytest.fixture
def resolvectl_status_healthy(fixtures_dir):
    """Load healthy resolvectl status."""
    return (fixtures_dir / "services" / "resolvectl_status_healthy.txt").read_text()


class TestDnsResolverHealth:
    """Tests for dns_resolver_health script."""

    def test_missing_resolv_conf_returns_critical(self, mock_context):
        """Returns 1 when resolv.conf is missing."""
        from scripts.baremetal import dns_resolver_health

        ctx = mock_context(
            tools_available=["systemctl", "resolvectl"],
            file_contents={},
            command_outputs={
                ("systemctl", "is-active", "systemd-resolved"): "inactive\n",
            },
        )
        output = Output()

        exit_code = dns_resolver_health.run(["--no-reachability", "--no-resolution"], output, ctx)

        assert exit_code == 1
        assert not output.data.get("healthy", True)
        assert any("does not exist" in i for i in output.data.get("issues", []))

    def test_no_nameservers_returns_critical(self, mock_context, resolv_conf_empty):
        """Returns 1 when no nameservers configured."""
        from scripts.baremetal import dns_resolver_health

        ctx = mock_context(
            tools_available=["systemctl", "resolvectl"],
            file_contents={
                "/etc/resolv.conf": resolv_conf_empty,
            },
            command_outputs={
                ("systemctl", "is-active", "systemd-resolved"): "inactive\n",
            },
        )
        output = Output()

        exit_code = dns_resolver_health.run(["--no-reachability", "--no-resolution"], output, ctx)

        assert exit_code == 1
        assert any("no nameservers" in i.lower() for i in output.data.get("issues", []))

    def test_healthy_resolv_conf_parsed(self, mock_context, resolv_conf_healthy, resolvectl_status_healthy):
        """Parses healthy resolv.conf correctly."""
        from scripts.baremetal import dns_resolver_health

        ctx = mock_context(
            tools_available=["systemctl", "resolvectl"],
            file_contents={
                "/etc/resolv.conf": resolv_conf_healthy,
            },
            command_outputs={
                ("systemctl", "is-active", "systemd-resolved"): "inactive\n",
            },
        )
        output = Output()

        exit_code = dns_resolver_health.run(["--no-reachability", "--no-resolution"], output, ctx)

        assert exit_code == 0
        assert len(output.data.get("nameservers", [])) == 3
        assert "8.8.8.8" in output.data.get("nameservers", [])

    def test_loopback_without_resolver_warns(self, mock_context, resolv_conf_loopback):
        """Warns when only loopback nameservers and no local resolver."""
        from scripts.baremetal import dns_resolver_health

        ctx = mock_context(
            tools_available=["systemctl", "resolvectl"],
            file_contents={
                "/etc/resolv.conf": resolv_conf_loopback,
            },
            command_outputs={
                ("systemctl", "is-active", "systemd-resolved"): "inactive\n",
            },
        )
        output = Output()

        exit_code = dns_resolver_health.run(["--no-reachability", "--no-resolution"], output, ctx)

        # Should have a warning about loopback-only configuration
        warnings = output.data.get("warnings", [])
        assert len(warnings) > 0
        assert any("loopback" in w.lower() for w in warnings)

    def test_verbose_includes_details(self, mock_context, resolv_conf_healthy, resolvectl_status_healthy):
        """--verbose includes full details."""
        from scripts.baremetal import dns_resolver_health

        ctx = mock_context(
            tools_available=["systemctl", "resolvectl"],
            file_contents={
                "/etc/resolv.conf": resolv_conf_healthy,
            },
            command_outputs={
                ("systemctl", "is-active", "systemd-resolved"): "active\n",
                ("resolvectl", "status"): resolvectl_status_healthy,
            },
        )
        output = Output()

        exit_code = dns_resolver_health.run(["--verbose", "--no-reachability", "--no-resolution"], output, ctx)

        assert "resolv_conf" in output.data
        assert "systemd_resolved" in output.data

    def test_skip_reachability_tests(self, mock_context, resolv_conf_healthy):
        """--no-reachability skips nameserver tests."""
        from scripts.baremetal import dns_resolver_health

        ctx = mock_context(
            tools_available=["systemctl"],
            file_contents={
                "/etc/resolv.conf": resolv_conf_healthy,
            },
            command_outputs={
                ("systemctl", "is-active", "systemd-resolved"): "inactive\n",
            },
        )
        output = Output()

        exit_code = dns_resolver_health.run(["--no-reachability", "--no-resolution"], output, ctx)

        # Should not have any reachability results
        assert len(output.data.get("nameserver_reachability", [])) == 0

    def test_invalid_timeout_returns_error(self, mock_context, resolv_conf_healthy):
        """Returns 2 for invalid timeout."""
        from scripts.baremetal import dns_resolver_health

        ctx = mock_context(
            tools_available=["systemctl"],
            file_contents={
                "/etc/resolv.conf": resolv_conf_healthy,
            },
            command_outputs={
                ("systemctl", "is-active", "systemd-resolved"): "inactive\n",
            },
        )
        output = Output()

        exit_code = dns_resolver_health.run(["--timeout", "0"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
