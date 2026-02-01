"""Tests for pcie_topology script."""

import pytest

from boxctl.core.output import Output


def make_pci_device_files(devices: list[dict]) -> dict[str, str]:
    """Build file_contents dict for MockContext with PCI device data."""
    files = {
        "/sys/bus/pci/devices": ""  # Directory marker
    }

    for dev in devices:
        addr = dev["address"]
        base = f"/sys/bus/pci/devices/{addr}"
        files[base] = ""  # Directory marker

        files[f"{base}/vendor"] = dev.get("vendor_id", "0x10de")
        files[f"{base}/device"] = dev.get("device_id", "0x1234")
        files[f"{base}/class"] = dev.get("class", "0x030000")

        if "driver" in dev:
            files[f"{base}/driver"] = dev["driver"]

        if "numa_node" in dev:
            files[f"{base}/numa_node"] = str(dev["numa_node"])

        if "iommu_group" in dev:
            files[f"{base}/iommu_group"] = str(dev["iommu_group"])

        if "current_link_speed" in dev:
            files[f"{base}/current_link_speed"] = dev["current_link_speed"]
        if "max_link_speed" in dev:
            files[f"{base}/max_link_speed"] = dev["max_link_speed"]
        if "current_link_width" in dev:
            files[f"{base}/current_link_width"] = dev["current_link_width"]
        if "max_link_width" in dev:
            files[f"{base}/max_link_width"] = dev["max_link_width"]

    return files


class TestPcieTopology:
    """Tests for pcie_topology script."""

    def test_no_pci_sysfs_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/bus/pci/devices doesn't exist."""
        from scripts.baremetal import pcie_topology

        ctx = mock_context(file_contents={})
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_devices_returns_error(self, mock_context):
        """Returns exit code 2 when no PCIe devices found."""
        from scripts.baremetal import pcie_topology

        ctx = mock_context(file_contents={
            "/sys/bus/pci/devices": ""
        })
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 2
        assert any("no pcie" in e.lower() for e in output.errors)

    def test_healthy_devices_return_ok(self, mock_context):
        """Returns 0 when all devices are properly configured."""
        from scripts.baremetal import pcie_topology

        files = make_pci_device_files([
            {
                "address": "0000:01:00.0",
                "vendor_id": "0x10de",
                "device_id": "0x2204",
                "class": "0x030000",  # Display controller
                "driver": "nvidia",
                "numa_node": 0,
                "iommu_group": 1,
                "current_link_speed": "16.0 GT/s PCIe",
                "max_link_speed": "16.0 GT/s PCIe",
                "current_link_width": "x16",
                "max_link_width": "x16",
            },
            {
                "address": "0000:02:00.0",
                "vendor_id": "0x8086",
                "device_id": "0x1521",
                "class": "0x020000",  # Network controller
                "driver": "igb",
                "numa_node": 0,
                "iommu_group": 2,
                "current_link_speed": "5.0 GT/s PCIe",
                "max_link_speed": "5.0 GT/s PCIe",
                "current_link_width": "x4",
                "max_link_width": "x4",
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_devices"] == 2
        assert output.data["summary"]["issue_count"] == 0

    def test_link_speed_degradation_detected(self, mock_context):
        """Detects when link speed is below maximum capability."""
        from scripts.baremetal import pcie_topology

        files = make_pci_device_files([
            {
                "address": "0000:01:00.0",
                "class": "0x030000",  # GPU
                "numa_node": 0,
                "iommu_group": 1,
                "current_link_speed": "8.0 GT/s PCIe",  # Running at Gen3
                "max_link_speed": "16.0 GT/s PCIe",    # Capable of Gen4
                "current_link_width": "x16",
                "max_link_width": "x16",
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["issue_count"] > 0
        issues = output.data["issues"]
        assert any("speed degraded" in i["message"].lower() for i in issues)

    def test_link_width_degradation_detected(self, mock_context):
        """Detects when link width is below maximum capability."""
        from scripts.baremetal import pcie_topology

        files = make_pci_device_files([
            {
                "address": "0000:01:00.0",
                "class": "0x030000",
                "numa_node": 0,
                "iommu_group": 1,
                "current_link_speed": "16.0 GT/s PCIe",
                "max_link_speed": "16.0 GT/s PCIe",
                "current_link_width": "x8",   # Only using 8 lanes
                "max_link_width": "x16",      # Capable of 16 lanes
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 1
        issues = output.data["issues"]
        assert any("width degraded" in i["message"].lower() for i in issues)

    def test_no_numa_affinity_detected(self, mock_context):
        """Detects devices without NUMA affinity."""
        from scripts.baremetal import pcie_topology

        files = make_pci_device_files([
            {
                "address": "0000:01:00.0",
                "class": "0x030000",  # GPU - should have NUMA
                "numa_node": -1,      # No NUMA affinity
                "iommu_group": 1,
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 1
        issues = output.data["issues"]
        assert any("numa" in i["message"].lower() for i in issues)

    def test_iommu_group_sharing_detected(self, mock_context):
        """Detects devices sharing IOMMU groups."""
        from scripts.baremetal import pcie_topology

        files = make_pci_device_files([
            {
                "address": "0000:01:00.0",
                "class": "0x030000",  # GPU
                "numa_node": 0,
                "iommu_group": 1,  # Same IOMMU group
            },
            {
                "address": "0000:01:00.1",
                "class": "0x040300",  # Audio (GPU audio)
                "numa_node": 0,
                "iommu_group": 1,  # Same IOMMU group
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 1
        issues = output.data["issues"]
        assert any("iommu group" in i["message"].lower() for i in issues)

    def test_no_link_check_option(self, mock_context):
        """--no-link-check skips link speed/width validation."""
        from scripts.baremetal import pcie_topology

        files = make_pci_device_files([
            {
                "address": "0000:01:00.0",
                "class": "0x030000",
                "numa_node": 0,
                "iommu_group": 1,
                "current_link_speed": "8.0 GT/s PCIe",
                "max_link_speed": "16.0 GT/s PCIe",  # Would be flagged
                "current_link_width": "x16",
                "max_link_width": "x16",
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = pcie_topology.run(["--no-link-check"], output, ctx)

        assert exit_code == 0  # No issues when link check disabled

    def test_bridge_devices_excluded_from_numa_check(self, mock_context):
        """Bridge devices (class 0x06) are not flagged for NUMA issues."""
        from scripts.baremetal import pcie_topology

        files = make_pci_device_files([
            {
                "address": "0000:00:00.0",
                "class": "0x060000",  # Bridge
                "numa_node": -1,      # No NUMA - OK for bridges
            }
        ])

        ctx = mock_context(file_contents=files)
        output = Output()

        exit_code = pcie_topology.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["issue_count"] == 0
