"""Tests for etcd_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def etcd_health_healthy(fixtures_dir):
    """Load healthy etcd health response."""
    return (fixtures_dir / "services" / "etcd_health_healthy.json").read_text()


@pytest.fixture
def etcd_health_unhealthy(fixtures_dir):
    """Load unhealthy etcd health response."""
    return (fixtures_dir / "services" / "etcd_health_unhealthy.json").read_text()


@pytest.fixture
def etcd_status_healthy(fixtures_dir):
    """Load healthy etcd status response."""
    return (fixtures_dir / "services" / "etcd_status_healthy.json").read_text()


@pytest.fixture
def etcd_member_list_healthy(fixtures_dir):
    """Load healthy etcd member list."""
    return (fixtures_dir / "services" / "etcd_member_list_healthy.json").read_text()


@pytest.fixture
def etcd_alarm_list_empty(fixtures_dir):
    """Load empty etcd alarm list."""
    return (fixtures_dir / "services" / "etcd_alarm_list_empty.json").read_text()


@pytest.fixture
def etcd_alarm_list_nospace(fixtures_dir):
    """Load etcd alarm list with NOSPACE alarm."""
    return (fixtures_dir / "services" / "etcd_alarm_list_nospace.json").read_text()


class TestEtcdHealth:
    """Tests for etcd_health script."""

    def test_missing_etcdctl_returns_error(self, mock_context):
        """Returns exit code 2 when etcdctl not available."""
        from scripts.baremetal import etcd_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = etcd_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("etcdctl" in e.lower() for e in output.errors)

    def test_cluster_healthy(
        self, mock_context, etcd_health_healthy, etcd_status_healthy,
        etcd_member_list_healthy, etcd_alarm_list_empty
    ):
        """Returns 0 when cluster is healthy."""
        from scripts.baremetal import etcd_health

        ctx = mock_context(
            tools_available=["etcdctl"],
            command_outputs={
                ("etcdctl", "endpoint", "health", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_health_healthy,
                ("etcdctl", "endpoint", "status", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_status_healthy,
                ("etcdctl", "member", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_member_list_healthy,
                ("etcdctl", "alarm", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_alarm_list_empty,
            },
        )
        output = Output()

        exit_code = etcd_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data.get("cluster_healthy") is True

    def test_endpoint_unhealthy_returns_issue(
        self, mock_context, etcd_health_unhealthy, etcd_status_healthy,
        etcd_member_list_healthy, etcd_alarm_list_empty
    ):
        """Returns 1 when endpoint is unhealthy."""
        from scripts.baremetal import etcd_health

        ctx = mock_context(
            tools_available=["etcdctl"],
            command_outputs={
                ("etcdctl", "endpoint", "health", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_health_unhealthy,
                ("etcdctl", "endpoint", "status", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_status_healthy,
                ("etcdctl", "member", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_member_list_healthy,
                ("etcdctl", "alarm", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_alarm_list_empty,
            },
        )
        output = Output()

        exit_code = etcd_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data.get("cluster_healthy") is False

    def test_alarm_active_returns_issue(
        self, mock_context, etcd_health_healthy, etcd_status_healthy,
        etcd_member_list_healthy, etcd_alarm_list_nospace
    ):
        """Returns 1 when alarms are active."""
        from scripts.baremetal import etcd_health

        ctx = mock_context(
            tools_available=["etcdctl"],
            command_outputs={
                ("etcdctl", "endpoint", "health", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_health_healthy,
                ("etcdctl", "endpoint", "status", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_status_healthy,
                ("etcdctl", "member", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_member_list_healthy,
                ("etcdctl", "alarm", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_alarm_list_nospace,
            },
        )
        output = Output()

        exit_code = etcd_health.run([], output, ctx)

        assert exit_code == 1
        issues = output.data.get("issues", [])
        assert any("NOSPACE" in i for i in issues)

    def test_verbose_includes_details(
        self, mock_context, etcd_health_healthy, etcd_status_healthy,
        etcd_member_list_healthy, etcd_alarm_list_empty
    ):
        """--verbose includes full details."""
        from scripts.baremetal import etcd_health

        ctx = mock_context(
            tools_available=["etcdctl"],
            command_outputs={
                ("etcdctl", "endpoint", "health", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_health_healthy,
                ("etcdctl", "endpoint", "status", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_status_healthy,
                ("etcdctl", "member", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_member_list_healthy,
                ("etcdctl", "alarm", "list", "--write-out=json",
                 "--endpoints", "http://127.0.0.1:2379"): etcd_alarm_list_empty,
            },
        )
        output = Output()

        exit_code = etcd_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "health_details" in output.data
        assert "status_details" in output.data
        assert "members_details" in output.data

    def test_custom_endpoints(
        self, mock_context, etcd_health_healthy, etcd_status_healthy,
        etcd_member_list_healthy, etcd_alarm_list_empty
    ):
        """--endpoints allows custom endpoint."""
        from scripts.baremetal import etcd_health

        custom_endpoint = "https://etcd.example.com:2379"
        ctx = mock_context(
            tools_available=["etcdctl"],
            command_outputs={
                ("etcdctl", "endpoint", "health", "--write-out=json",
                 "--endpoints", custom_endpoint): etcd_health_healthy,
                ("etcdctl", "endpoint", "status", "--write-out=json",
                 "--endpoints", custom_endpoint): etcd_status_healthy,
                ("etcdctl", "member", "list", "--write-out=json",
                 "--endpoints", custom_endpoint): etcd_member_list_healthy,
                ("etcdctl", "alarm", "list", "--write-out=json",
                 "--endpoints", custom_endpoint): etcd_alarm_list_empty,
            },
        )
        output = Output()

        exit_code = etcd_health.run(["--endpoints", custom_endpoint], output, ctx)

        assert exit_code == 0

    def test_connection_failure_returns_error(self, mock_context):
        """Returns 1 when connection fails."""
        from scripts.baremetal import etcd_health
        import subprocess

        # Create mock that returns failure for all etcd commands
        ctx = mock_context(
            tools_available=["etcdctl"],
            command_outputs={},
        )
        # Override run to simulate connection failure for all etcd commands
        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, returncode=1, stdout="",
                stderr="Error: connection refused"
            )
        ctx.run = mock_run
        output = Output()

        exit_code = etcd_health.run([], output, ctx)

        # Should handle error and return issue
        assert exit_code == 1
        assert output.data.get("cluster_healthy") is False
