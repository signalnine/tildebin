#!/usr/bin/env python3
# boxctl:
#   category: baremetal/virtualization
#   tags: [health, libvirt, kvm, vm, virtualization]
#   requires: [virsh]
#   privilege: root
#   related: [disk_health, memory_usage, cpu_usage]
#   brief: Monitor libvirt/KVM hypervisor and VM health

"""
Monitor libvirt/KVM hypervisor and virtual machine health.

Monitors libvirt-managed virtual machines and hypervisor for issues:
- VM states (running, paused, shutoff, crashed)
- VM autostart configuration
- Storage pool health
- Network health

Returns exit code 0 if healthy, 1 if issues found, 2 on error.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_libvirt_running(context: Context) -> tuple[bool, str]:
    """Check if libvirtd is running and accessible."""
    result = context.run(["virsh", "version"], check=False)
    if result.returncode == 0:
        return True, result.stdout
    return False, result.stderr


def get_hypervisor_info(context: Context) -> dict[str, Any]:
    """Get hypervisor information."""
    info = {
        "connected": False,
        "hypervisor": None,
        "api_version": None,
        "host_cpu": None,
        "host_memory_mb": None,
    }

    # Get version info
    result = context.run(["virsh", "version"], check=False)
    if result.returncode == 0:
        info["connected"] = True
        for line in result.stdout.split("\n"):
            if "hypervisor:" in line.lower():
                info["hypervisor"] = line.split(":", 1)[1].strip() if ":" in line else None
            elif "API:" in line:
                info["api_version"] = line.split(":", 1)[1].strip() if ":" in line else None

    # Get node info
    result = context.run(["virsh", "nodeinfo"], check=False)
    if result.returncode == 0:
        for line in result.stdout.split("\n"):
            if line.startswith("CPU model:"):
                info["host_cpu"] = line.split(":", 1)[1].strip()
            elif line.startswith("Memory size:"):
                mem_str = line.split(":", 1)[1].strip()
                try:
                    mem_kib = int(mem_str.split()[0])
                    info["host_memory_mb"] = mem_kib // 1024
                except (ValueError, IndexError):
                    pass

    return info


def get_vm_list(context: Context) -> list[dict[str, Any]]:
    """Get list of all VMs (running and stopped)."""
    result = context.run(["virsh", "list", "--all"], check=False)
    if result.returncode != 0:
        return []

    vms = []
    lines = result.stdout.strip().split("\n")
    # Skip header lines
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 2:
            # Format: ID Name State (ID is - for stopped VMs)
            vm_id = parts[0] if parts[0] != "-" else None
            vm_name = parts[1]
            vm_state = " ".join(parts[2:]) if len(parts) > 2 else "unknown"
            vms.append({
                "id": vm_id,
                "name": vm_name,
                "state": vm_state,
            })

    return vms


def get_vm_details(vm_name: str, context: Context) -> dict[str, Any]:
    """Get detailed information about a VM."""
    details = {
        "name": vm_name,
        "vcpus": None,
        "memory_mb": None,
        "autostart": None,
        "persistent": None,
    }

    result = context.run(["virsh", "dominfo", vm_name], check=False)
    if result.returncode == 0:
        for line in result.stdout.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "cpu(s)":
                    try:
                        details["vcpus"] = int(value)
                    except ValueError:
                        pass
                elif key == "max memory":
                    try:
                        mem_kib = int(value.split()[0])
                        details["memory_mb"] = mem_kib // 1024
                    except (ValueError, IndexError):
                        pass
                elif key == "autostart":
                    details["autostart"] = value.lower() == "enable"
                elif key == "persistent":
                    details["persistent"] = value.lower() == "yes"

    return details


def get_storage_pools(context: Context) -> list[dict[str, str]]:
    """Get storage pool status."""
    result = context.run(["virsh", "pool-list", "--all"], check=False)
    if result.returncode != 0:
        return []

    pools = []
    lines = result.stdout.strip().split("\n")
    # Skip header lines
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 2:
            pools.append({
                "name": parts[0],
                "state": parts[1] if len(parts) > 1 else "unknown",
                "autostart": parts[2] if len(parts) > 2 else "unknown",
            })

    return pools


def get_networks(context: Context) -> list[dict[str, str]]:
    """Get virtual network status."""
    result = context.run(["virsh", "net-list", "--all"], check=False)
    if result.returncode != 0:
        return []

    networks = []
    lines = result.stdout.strip().split("\n")
    # Skip header lines
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 2:
            networks.append({
                "name": parts[0],
                "state": parts[1] if len(parts) > 1 else "unknown",
                "autostart": parts[2] if len(parts) > 2 else "unknown",
                "persistent": parts[3] if len(parts) > 3 else "unknown",
            })

    return networks


def analyze_health(
    hypervisor_info: dict[str, Any],
    vms: list[dict[str, Any]],
    vm_details: list[dict[str, Any]],
    pools: list[dict[str, str]],
    networks: list[dict[str, str]],
    check_autostart: bool,
) -> tuple[str, list[str]]:
    """Analyze overall health and generate warnings."""
    warnings = []
    status = "healthy"

    # Check hypervisor
    if not hypervisor_info["connected"]:
        status = "critical"
        warnings.append("Cannot connect to libvirt daemon")
        return status, warnings

    # Map VM names to details
    details_by_name = {d["name"]: d for d in vm_details}

    # Check VMs
    for vm in vms:
        vm_state = vm["state"].lower()

        if "crash" in vm_state:
            status = "critical"
            warnings.append(f"VM {vm['name']} is crashed")
        elif "paused" in vm_state:
            if status != "critical":
                status = "warning"
            warnings.append(f"VM {vm['name']} is paused")

        # Check autostart for running VMs
        if check_autostart and "running" in vm_state:
            details = details_by_name.get(vm["name"], {})
            if details.get("autostart") is False:
                if status != "critical":
                    status = "warning"
                warnings.append(
                    f"VM {vm['name']} is running but autostart is disabled"
                )

    # Check storage pools
    for pool in pools:
        if pool["state"].lower() != "active":
            if status != "critical":
                status = "warning"
            warnings.append(
                f"Storage pool {pool['name']} is not active ({pool['state']})"
            )

    # Check networks
    for net in networks:
        if net["state"].lower() != "active" and net["autostart"].lower() == "yes":
            if status != "critical":
                status = "warning"
            warnings.append(
                f"Network {net['name']} is not active but has autostart enabled"
            )

    return status, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor libvirt/KVM hypervisor health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--vm", metavar="NAME", help="Check specific VM only")
    parser.add_argument(
        "--check-autostart", action="store_true",
        help="Warn if running VMs do not have autostart enabled"
    )
    parser.add_argument("--skip-pools", action="store_true", help="Skip storage pool checks")
    parser.add_argument("--skip-networks", action="store_true", help="Skip network checks")
    opts = parser.parse_args(args)

    # Check for virsh tool
    if not context.check_tool("virsh"):
        output.error("virsh not found. Install libvirt-clients package.")
        return 2

    # Check if libvirt is running
    running, _ = check_libvirt_running(context)
    if not running:
        output.error("Cannot connect to libvirt daemon.")
        return 2

    # Gather information
    hypervisor_info = get_hypervisor_info(context)
    vms = get_vm_list(context)

    # Filter to specific VM if requested
    if opts.vm:
        vms = [vm for vm in vms if vm["name"] == opts.vm]
        if not vms:
            output.error(f"VM '{opts.vm}' not found")
            return 2

    pools = [] if opts.skip_pools else get_storage_pools(context)
    networks = [] if opts.skip_networks else get_networks(context)

    # Get VM details
    vm_details = []
    for vm in vms:
        details = get_vm_details(vm["name"], context)
        details["state"] = vm["state"]
        details["id"] = vm["id"]

        # Determine VM status
        vm_state = vm["state"].lower()
        if "crash" in vm_state:
            details["status"] = "critical"
        elif "paused" in vm_state:
            details["status"] = "warning"
        elif "running" in vm_state:
            details["status"] = "running"
        elif "shut" in vm_state:
            details["status"] = "stopped"
        else:
            details["status"] = "unknown"

        vm_details.append(details)

    # Analyze health
    status, warnings = analyze_health(
        hypervisor_info, vms, vm_details, pools, networks, opts.check_autostart
    )

    # Build result
    result = {
        "hypervisor": hypervisor_info,
        "vms": vm_details,
        "summary": {
            "status": status,
            "total_vms": len(vms),
            "running_vms": sum(1 for vm in vms if "running" in vm["state"].lower()),
            "stopped_vms": sum(1 for vm in vms if "shut" in vm["state"].lower()),
        },
        "warnings": warnings,
    }

    if opts.verbose or not opts.skip_pools:
        result["storage_pools"] = pools
    if opts.verbose or not opts.skip_networks:
        result["networks"] = networks

    output.emit(result)

    # Set summary
    running = result["summary"]["running_vms"]
    stopped = result["summary"]["stopped_vms"]
    output.set_summary(f"{status.upper()}: {running} running, {stopped} stopped, {len(warnings)} warnings")

    # Log warnings
    for warning in warnings:
        output.warning(warning)

    # Exit code
    if status == "critical":
        return 1
    elif status == "warning":
        return 1
    else:
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
