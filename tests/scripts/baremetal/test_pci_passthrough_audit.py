"""Tests for pci_passthrough_audit script."""

import json
import pytest

from boxctl.core.output import Output
from tests.conftest import MockContext


class TestPciPassthroughAudit:
    """Tests for pci_passthrough_audit."""

    def test_no_pci_sysfs(self):
        """Returns exit code 2 when /sys/bus/pci/devices not found."""
        from scripts.baremetal.pci_passthrough_audit import run

        ctx = MockContext(file_contents={})
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 2
        assert any("/sys/bus/pci/devices" in e for e in output.errors)

    def test_no_vfio_devices(self):
        """Returns exit 0 with INFO when vfio-pci driver dir not present."""
        from scripts.baremetal.pci_passthrough_audit import run

        ctx = MockContext(file_contents={
            # PCI sysfs exists (is_dir needs a child path)
            "/sys/bus/pci/devices/0000:00:00.0/vendor": "0x8086",
        })
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data.get("vfio_device_count") == 0
        assert "No VFIO passthrough configured" in output.summary

    def test_healthy_passthrough(self):
        """VFIO device in isolated IOMMU group returns exit 0."""
        from scripts.baremetal.pci_passthrough_audit import run

        ctx = MockContext(file_contents={
            # PCI sysfs exists
            "/sys/bus/pci/devices/0000:01:00.0/vendor": "0x10de",
            # VFIO driver dir exists with one device
            "/sys/bus/pci/drivers/vfio-pci/0000:01:00.0/config": "",
            # IOMMU group 1 has only this device
            "/sys/kernel/iommu_groups/1/devices/0000:01:00.0/vendor": "0x10de",
            # Driver symlinks
            "/sys/bus/pci/devices/0000:01:00.0/driver": "../../../../bus/pci/drivers/vfio-pci",
        })
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 0
        assert output.data.get("status") == "healthy"
        assert output.data.get("vfio_device_count") == 1
        assert len(output.data.get("issues", [])) == 0

    def test_mixed_group(self):
        """VFIO and non-VFIO devices in same IOMMU group returns exit 1 WARNING."""
        from scripts.baremetal.pci_passthrough_audit import run

        ctx = MockContext(file_contents={
            # PCI sysfs exists
            "/sys/bus/pci/devices/0000:01:00.0/vendor": "0x10de",
            "/sys/bus/pci/devices/0000:01:00.1/vendor": "0x10de",
            # VFIO driver dir exists with one device (GPU)
            "/sys/bus/pci/drivers/vfio-pci/0000:01:00.0/config": "",
            # IOMMU group 2 has BOTH devices
            "/sys/kernel/iommu_groups/2/devices/0000:01:00.0/vendor": "0x10de",
            "/sys/kernel/iommu_groups/2/devices/0000:01:00.1/vendor": "0x10de",
            # Driver symlinks: .0 is vfio-pci, .1 is snd_hda_intel
            "/sys/bus/pci/devices/0000:01:00.0/driver": "../../../../bus/pci/drivers/vfio-pci",
            "/sys/bus/pci/devices/0000:01:00.1/driver": "../../../../bus/pci/drivers/snd_hda_intel",
        })
        output = Output()

        exit_code = run([], output, ctx)

        assert exit_code == 1
        assert output.data.get("status") == "warning"
        issues = output.data.get("issues", [])
        assert len(issues) == 1
        assert issues[0]["type"] == "mixed_iommu_group"
        assert issues[0]["severity"] == "warning"
        assert "0000:01:00.0" in issues[0]["vfio_devices"]
        assert "0000:01:00.1" in issues[0]["non_vfio_devices"]

    def test_json_output(self, capsys):
        """JSON output contains expected device and group data structure."""
        from scripts.baremetal.pci_passthrough_audit import run

        ctx = MockContext(file_contents={
            # PCI sysfs exists
            "/sys/bus/pci/devices/0000:01:00.0/vendor": "0x10de",
            # VFIO driver dir exists with one device
            "/sys/bus/pci/drivers/vfio-pci/0000:01:00.0/config": "",
            # IOMMU group 1 has only this device
            "/sys/kernel/iommu_groups/1/devices/0000:01:00.0/vendor": "0x10de",
            # Driver symlink
            "/sys/bus/pci/devices/0000:01:00.0/driver": "../../../../bus/pci/drivers/vfio-pci",
        })
        output = Output()

        exit_code = run(["--format", "json"], output, ctx)

        assert exit_code == 0

        # Verify emitted data structure
        data = output.data
        assert "status" in data
        assert "vfio_device_count" in data
        assert "iommu_group_count" in data
        assert "devices" in data
        assert "issues" in data
        assert isinstance(data["devices"], list)
        assert len(data["devices"]) == 1

        device = data["devices"][0]
        assert "address" in device
        assert "driver" in device
        assert "iommu_group" in device
        assert "is_vfio" in device
        assert device["address"] == "0000:01:00.0"
        assert device["driver"] == "vfio-pci"
        assert device["iommu_group"] == "1"
        assert device["is_vfio"] is True
