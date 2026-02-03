#!/usr/bin/env python3
# boxctl:
#   category: baremetal/boot
#   tags: [inventory, firmware, bios, hardware]
#   requires: []
#   privilege: optional
#   related: [efi_boot_audit, grub_config_audit]
#   brief: Collect firmware version inventory from system

"""
Collect firmware version inventory from baremetal systems.

Gathers firmware and version information including:
- BIOS/UEFI version and release date
- BMC/IPMI firmware version (if accessible)
- CPU microcode version
- Network adapter firmware
- System and baseboard information
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# DMI sysfs paths
DMI_PATH = "/sys/class/dmi/id"


def get_bios_info(context: Context) -> dict[str, Any]:
    """Get BIOS/UEFI information from DMI."""
    info = {
        "vendor": None,
        "version": None,
        "release_date": None,
    }

    paths = {
        "vendor": f"{DMI_PATH}/bios_vendor",
        "version": f"{DMI_PATH}/bios_version",
        "release_date": f"{DMI_PATH}/bios_date",
    }

    for key, path in paths.items():
        if context.file_exists(path):
            try:
                info[key] = context.read_file(path).strip()
            except Exception:
                pass

    return info


def get_system_info(context: Context) -> dict[str, Any]:
    """Get system/chassis information."""
    info = {
        "manufacturer": None,
        "product_name": None,
        "version": None,
        "serial_number": None,
    }

    paths = {
        "manufacturer": f"{DMI_PATH}/sys_vendor",
        "product_name": f"{DMI_PATH}/product_name",
        "version": f"{DMI_PATH}/product_version",
        "serial_number": f"{DMI_PATH}/product_serial",
    }

    for key, path in paths.items():
        if context.file_exists(path):
            try:
                info[key] = context.read_file(path).strip()
            except Exception:
                pass

    return info


def get_baseboard_info(context: Context) -> dict[str, Any]:
    """Get baseboard/motherboard information."""
    info = {
        "manufacturer": None,
        "product_name": None,
        "version": None,
    }

    paths = {
        "manufacturer": f"{DMI_PATH}/board_vendor",
        "product_name": f"{DMI_PATH}/board_name",
        "version": f"{DMI_PATH}/board_version",
    }

    for key, path in paths.items():
        if context.file_exists(path):
            try:
                info[key] = context.read_file(path).strip()
            except Exception:
                pass

    return info


def get_cpu_microcode(context: Context) -> dict[str, Any]:
    """Get CPU microcode version."""
    info = {
        "version": None,
    }

    cpuinfo_path = "/proc/cpuinfo"
    if context.file_exists(cpuinfo_path):
        try:
            content = context.read_file(cpuinfo_path)
            for line in content.split("\n"):
                if line.startswith("microcode"):
                    parts = line.split(":")
                    if len(parts) == 2:
                        info["version"] = parts[1].strip()
                    break
        except Exception:
            pass

    return info


def get_bmc_info(context: Context) -> dict[str, Any]:
    """Get BMC/IPMI firmware information."""
    info = {
        "version": None,
        "manufacturer": None,
        "available": False,
    }

    if not context.check_tool("ipmitool"):
        return info

    try:
        result = context.run(["ipmitool", "mc", "info"], check=False)
        if result.returncode == 0:
            info["available"] = True
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Firmware Revision"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        info["version"] = parts[1].strip()
                elif line.startswith("Manufacturer Name"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        info["manufacturer"] = parts[1].strip()
    except Exception:
        pass

    return info


def get_network_firmware(context: Context) -> list[dict[str, Any]]:
    """Get network adapter firmware versions."""
    devices = []

    if not context.check_tool("ethtool"):
        return devices

    # Get list of network interfaces
    net_path = "/sys/class/net"
    try:
        interfaces = context.glob("*", net_path)
        for iface_path in interfaces:
            iface = iface_path.split("/")[-1]

            # Skip virtual interfaces
            if iface.startswith(("lo", "docker", "br-", "veth", "virbr")):
                continue

            # Check if it's a physical device
            device_path = f"{net_path}/{iface}/device"
            if not context.file_exists(device_path):
                continue

            dev_info = {
                "interface": iface,
                "driver": None,
                "firmware": None,
            }

            # Get firmware version using ethtool
            try:
                result = context.run(["ethtool", "-i", iface], check=False)
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if line.startswith("firmware-version:"):
                            dev_info["firmware"] = line.split(":", 1)[1].strip()
                        elif line.startswith("driver:"):
                            dev_info["driver"] = line.split(":", 1)[1].strip()
            except Exception:
                pass

            devices.append(dev_info)

    except Exception:
        pass

    return devices


def get_kernel_info(context: Context) -> dict[str, Any]:
    """Get kernel version and related info."""
    info = {
        "release": None,
        "version": None,
        "machine": None,
    }

    try:
        result = context.run(["uname", "-r"], check=False)
        if result.returncode == 0:
            info["release"] = result.stdout.strip()

        result = context.run(["uname", "-m"], check=False)
        if result.returncode == 0:
            info["machine"] = result.stdout.strip()
    except Exception:
        pass

    return info


def get_hostname(context: Context) -> str | None:
    """Get system hostname."""
    try:
        result = context.run(["hostname", "-f"], check=False)
        if result.returncode == 0:
            return result.stdout.strip()
        result = context.run(["hostname"], check=False)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def has_data(value: Any) -> bool:
    """Check if a value contains meaningful data."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, dict):
        return any(has_data(v) for v in value.values())
    return True


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = data collected, 1 = partial data, 2 = error
    """
    parser = argparse.ArgumentParser(description="Collect firmware version inventory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show additional details")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for uname (basic requirement)
    if not context.check_tool("uname"):
        output.error("uname not found - basic Linux tools required")

        output.render(opts.format, "Collect firmware version inventory from system")
        return 2

    # Collect inventory
    inventory = {
        "hostname": get_hostname(context),
        "kernel": get_kernel_info(context),
        "system": get_system_info(context),
        "baseboard": get_baseboard_info(context),
        "bios": get_bios_info(context),
        "cpu_microcode": get_cpu_microcode(context),
        "bmc": get_bmc_info(context),
        "network": get_network_firmware(context),
    }

    output.emit(inventory)

    # Build summary
    components = []
    if has_data(inventory.get("bios")):
        bios_ver = inventory["bios"].get("version", "unknown")
        components.append(f"BIOS: {bios_ver}")
    if has_data(inventory.get("cpu_microcode")):
        mc_ver = inventory["cpu_microcode"].get("version", "unknown")
        components.append(f"microcode: {mc_ver}")
    if inventory.get("bmc", {}).get("available"):
        bmc_ver = inventory["bmc"].get("version", "unknown")
        components.append(f"BMC: {bmc_ver}")

    if components:
        output.set_summary(", ".join(components))
    else:
        output.set_summary("No firmware info available")

    # Check if we got basic info
    has_bios = has_data(inventory.get("bios"))
    has_system = has_data(inventory.get("system"))

    if not has_bios and not has_system:

        output.render(opts.format, "Collect firmware version inventory from system")
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
