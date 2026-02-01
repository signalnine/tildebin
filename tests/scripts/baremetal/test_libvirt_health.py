"""Tests for libvirt_health script."""

import pytest
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def virsh_version(fixtures_dir):
    """Load virsh version output."""
    return (fixtures_dir / "storage" / "virsh_version.txt").read_text()


@pytest.fixture
def virsh_nodeinfo(fixtures_dir):
    """Load virsh nodeinfo output."""
    return (fixtures_dir / "storage" / "virsh_nodeinfo.txt").read_text()


@pytest.fixture
def virsh_list_all(fixtures_dir):
    """Load virsh list --all output."""
    return (fixtures_dir / "storage" / "virsh_list_all.txt").read_text()


@pytest.fixture
def virsh_list_crashed(fixtures_dir):
    """Load virsh list with crashed VM."""
    return (fixtures_dir / "storage" / "virsh_list_crashed.txt").read_text()


@pytest.fixture
def virsh_list_paused(fixtures_dir):
    """Load virsh list with paused VM."""
    return (fixtures_dir / "storage" / "virsh_list_paused.txt").read_text()


@pytest.fixture
def virsh_dominfo_webserver(fixtures_dir):
    """Load virsh dominfo for webserver."""
    return (fixtures_dir / "storage" / "virsh_dominfo_webserver.txt").read_text()


@pytest.fixture
def virsh_dominfo_no_autostart(fixtures_dir):
    """Load virsh dominfo without autostart."""
    return (fixtures_dir / "storage" / "virsh_dominfo_no_autostart.txt").read_text()


@pytest.fixture
def virsh_pool_list(fixtures_dir):
    """Load virsh pool-list output."""
    return (fixtures_dir / "storage" / "virsh_pool_list.txt").read_text()


@pytest.fixture
def virsh_pool_list_inactive(fixtures_dir):
    """Load virsh pool-list with inactive pool."""
    return (fixtures_dir / "storage" / "virsh_pool_list_inactive.txt").read_text()


@pytest.fixture
def virsh_net_list(fixtures_dir):
    """Load virsh net-list output."""
    return (fixtures_dir / "storage" / "virsh_net_list.txt").read_text()


class TestLibvirtHealth:
    """Tests for libvirt_health script."""

    def test_missing_virsh_returns_error(self, mock_context):
        """Returns exit code 2 when virsh not available."""
        from scripts.baremetal import libvirt_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = libvirt_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("virsh" in e.lower() for e in output.errors)

    def test_healthy_hypervisor(
        self,
        mock_context,
        virsh_version,
        virsh_nodeinfo,
        virsh_list_all,
        virsh_dominfo_webserver,
        virsh_pool_list,
        virsh_net_list,
    ):
        """Returns 0 when hypervisor and VMs are healthy."""
        from scripts.baremetal import libvirt_health

        ctx = mock_context(
            tools_available=["virsh"],
            command_outputs={
                ("virsh", "version"): virsh_version,
                ("virsh", "nodeinfo"): virsh_nodeinfo,
                ("virsh", "list", "--all"): virsh_list_all,
                ("virsh", "dominfo", "webserver"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "database"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "testvm"): virsh_dominfo_webserver,
                ("virsh", "pool-list", "--all"): virsh_pool_list,
                ("virsh", "net-list", "--all"): virsh_net_list,
            }
        )
        output = Output()

        exit_code = libvirt_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["status"] == "healthy"

    def test_crashed_vm_critical(
        self,
        mock_context,
        virsh_version,
        virsh_nodeinfo,
        virsh_list_crashed,
        virsh_dominfo_webserver,
        virsh_pool_list,
        virsh_net_list,
    ):
        """Returns 1 when a VM is crashed."""
        from scripts.baremetal import libvirt_health

        ctx = mock_context(
            tools_available=["virsh"],
            command_outputs={
                ("virsh", "version"): virsh_version,
                ("virsh", "nodeinfo"): virsh_nodeinfo,
                ("virsh", "list", "--all"): virsh_list_crashed,
                ("virsh", "dominfo", "webserver"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "database"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "testvm"): virsh_dominfo_webserver,
                ("virsh", "pool-list", "--all"): virsh_pool_list,
                ("virsh", "net-list", "--all"): virsh_net_list,
            }
        )
        output = Output()

        exit_code = libvirt_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["status"] == "critical"
        assert any("crashed" in w.lower() for w in output.data["warnings"])

    def test_paused_vm_warning(
        self,
        mock_context,
        virsh_version,
        virsh_nodeinfo,
        virsh_list_paused,
        virsh_dominfo_webserver,
        virsh_pool_list,
        virsh_net_list,
    ):
        """Returns 1 when a VM is paused."""
        from scripts.baremetal import libvirt_health

        ctx = mock_context(
            tools_available=["virsh"],
            command_outputs={
                ("virsh", "version"): virsh_version,
                ("virsh", "nodeinfo"): virsh_nodeinfo,
                ("virsh", "list", "--all"): virsh_list_paused,
                ("virsh", "dominfo", "webserver"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "database"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "testvm"): virsh_dominfo_webserver,
                ("virsh", "pool-list", "--all"): virsh_pool_list,
                ("virsh", "net-list", "--all"): virsh_net_list,
            }
        )
        output = Output()

        exit_code = libvirt_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["status"] == "warning"
        assert any("paused" in w.lower() for w in output.data["warnings"])

    def test_inactive_pool_warning(
        self,
        mock_context,
        virsh_version,
        virsh_nodeinfo,
        virsh_list_all,
        virsh_dominfo_webserver,
        virsh_pool_list_inactive,
        virsh_net_list,
    ):
        """Returns 1 when a storage pool is inactive."""
        from scripts.baremetal import libvirt_health

        ctx = mock_context(
            tools_available=["virsh"],
            command_outputs={
                ("virsh", "version"): virsh_version,
                ("virsh", "nodeinfo"): virsh_nodeinfo,
                ("virsh", "list", "--all"): virsh_list_all,
                ("virsh", "dominfo", "webserver"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "database"): virsh_dominfo_webserver,
                ("virsh", "dominfo", "testvm"): virsh_dominfo_webserver,
                ("virsh", "pool-list", "--all"): virsh_pool_list_inactive,
                ("virsh", "net-list", "--all"): virsh_net_list,
            }
        )
        output = Output()

        exit_code = libvirt_health.run([], output, ctx)

        assert exit_code == 1
        assert any("pool" in w.lower() and "not active" in w.lower() for w in output.data["warnings"])

    def test_autostart_check(
        self,
        mock_context,
        virsh_version,
        virsh_nodeinfo,
        virsh_list_all,
        virsh_dominfo_no_autostart,
        virsh_pool_list,
        virsh_net_list,
    ):
        """--check-autostart warns when running VM lacks autostart."""
        from scripts.baremetal import libvirt_health

        ctx = mock_context(
            tools_available=["virsh"],
            command_outputs={
                ("virsh", "version"): virsh_version,
                ("virsh", "nodeinfo"): virsh_nodeinfo,
                ("virsh", "list", "--all"): virsh_list_all,
                ("virsh", "dominfo", "webserver"): virsh_dominfo_no_autostart,
                ("virsh", "dominfo", "database"): virsh_dominfo_no_autostart,
                ("virsh", "dominfo", "testvm"): virsh_dominfo_no_autostart,
                ("virsh", "pool-list", "--all"): virsh_pool_list,
                ("virsh", "net-list", "--all"): virsh_net_list,
            }
        )
        output = Output()

        exit_code = libvirt_health.run(["--check-autostart"], output, ctx)

        assert exit_code == 1
        assert any("autostart" in w.lower() for w in output.data["warnings"])

    def test_specific_vm_filter(
        self,
        mock_context,
        virsh_version,
        virsh_nodeinfo,
        virsh_list_all,
        virsh_dominfo_webserver,
        virsh_pool_list,
        virsh_net_list,
    ):
        """--vm filters to specific VM."""
        from scripts.baremetal import libvirt_health

        ctx = mock_context(
            tools_available=["virsh"],
            command_outputs={
                ("virsh", "version"): virsh_version,
                ("virsh", "nodeinfo"): virsh_nodeinfo,
                ("virsh", "list", "--all"): virsh_list_all,
                ("virsh", "dominfo", "webserver"): virsh_dominfo_webserver,
                ("virsh", "pool-list", "--all"): virsh_pool_list,
                ("virsh", "net-list", "--all"): virsh_net_list,
            }
        )
        output = Output()

        exit_code = libvirt_health.run(["--vm", "webserver"], output, ctx)

        assert exit_code == 0
        assert len(output.data["vms"]) == 1
        assert output.data["vms"][0]["name"] == "webserver"
