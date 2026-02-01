#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, infiniband, rdma, hpc, connectivity]
#   requires: []
#   privilege: root
#   related: [fc_health, iscsi_health, scsi_error_monitor]
#   brief: Monitor InfiniBand and RDMA health for HPC environments

"""
Monitor InfiniBand (IB) and RDMA health for high-performance computing environments.

Checks InfiniBand fabric health by reading from /sys/class/infiniband including:
- Port states and physical link status
- Error counters (symbol errors, link recoveries, CRC errors)
- Subnet manager connectivity
- RDMA device availability

Returns exit code 1 if any IB ports have issues or errors detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# IB port attributes to read
IB_PORT_ATTRS = ["state", "phys_state", "rate", "lid", "sm_lid", "link_layer"]

# IB device attributes to read
IB_DEVICE_ATTRS = ["node_type", "node_guid", "fw_ver"]

# Error counter names
IB_ERROR_COUNTERS = [
    "symbol_error",
    "link_error_recovery",
    "link_downed",
    "port_rcv_errors",
    "port_xmit_discards",
    "local_link_integrity_errors",
]


def get_ib_devices(context: Context) -> list[dict[str, Any]]:
    """Get list of InfiniBand devices from /sys/class/infiniband."""
    devices: list[dict[str, Any]] = []
    ib_path = "/sys/class/infiniband"

    if not context.file_exists(ib_path):
        return devices

    try:
        device_paths = context.glob("*", root=ib_path)
    except Exception:
        return devices

    for device_path in device_paths:
        device_name = device_path.split("/")[-1]
        device: dict[str, Any] = {
            "name": device_name,
            "path": device_path,
            "ports": [],
        }

        # Read device attributes
        for attr in IB_DEVICE_ATTRS:
            attr_path = f"{device_path}/{attr}"
            if context.file_exists(attr_path):
                try:
                    device[attr] = context.read_file(attr_path).strip()
                except Exception:
                    pass

        # Get port information
        ports_path = f"{device_path}/ports"
        if context.file_exists(ports_path):
            try:
                port_paths = context.glob("*", root=ports_path)
                for port_path in sorted(port_paths):
                    port_name = port_path.split("/")[-1]
                    try:
                        port_num = int(port_name)
                    except ValueError:
                        continue

                    port_info: dict[str, Any] = {
                        "port": port_num,
                        "path": port_path,
                    }

                    # Read port attributes
                    for attr in IB_PORT_ATTRS:
                        attr_path = f"{port_path}/{attr}"
                        if context.file_exists(attr_path):
                            try:
                                value = context.read_file(attr_path).strip()
                                # Parse state values like "4: ACTIVE"
                                if ":" in value:
                                    value = value.split(":", 1)[1].strip()
                                port_info[attr] = value
                            except Exception:
                                pass

                    # Get counters
                    counters_path = f"{port_path}/counters"
                    if context.file_exists(counters_path):
                        port_info["counters"] = get_port_counters(counters_path, context)

                    device["ports"].append(port_info)
            except Exception:
                pass

        devices.append(device)

    return devices


def get_port_counters(counters_path: str, context: Context) -> dict[str, int]:
    """Get error counters for an IB port."""
    counters: dict[str, int] = {}

    for counter in IB_ERROR_COUNTERS:
        counter_path = f"{counters_path}/{counter}"
        if context.file_exists(counter_path):
            try:
                value = context.read_file(counter_path).strip()
                counters[counter] = int(value)
            except (ValueError, Exception):
                pass

    return counters


def check_sm_status(context: Context) -> dict[str, Any] | None:
    """Check subnet manager status using sminfo."""
    if not context.check_tool("sminfo"):
        return None

    result = context.run(["sminfo"], check=False)
    if result.returncode != 0:
        return None

    sm_info: dict[str, Any] = {"raw": result.stdout.strip()}

    # Extract SM state
    match = re.search(r"state:(\d+)\s+(\w+)", result.stdout)
    if match:
        sm_info["state_num"] = int(match.group(1))
        sm_info["state"] = match.group(2)

    # Extract SM LID
    match = re.search(r"sm lid:(\d+)", result.stdout)
    if match:
        sm_info["sm_lid"] = int(match.group(1))

    return sm_info


def analyze_health(
    devices: list[dict[str, Any]],
    sm_status: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Analyze InfiniBand health and generate issues list."""
    issues: list[dict[str, Any]] = []

    if not devices:
        issues.append({
            "severity": "ERROR",
            "type": "no_devices",
            "message": "No InfiniBand devices found. Check if IB kernel modules are loaded.",
        })
        return issues

    for device in devices:
        device_name = device["name"]

        for port in device.get("ports", []):
            port_num = port["port"]
            port_id = f"{device_name}:{port_num}"

            # Check port state
            state = port.get("state", "UNKNOWN")
            phys_state = port.get("phys_state", "UNKNOWN")

            if state != "ACTIVE":
                severity = "WARNING" if state in ["INIT", "ARMED"] else "ERROR"
                issues.append({
                    "severity": severity,
                    "type": "port_not_active",
                    "device": device_name,
                    "port": port_num,
                    "state": state,
                    "message": f"Port {port_id} is not ACTIVE (state={state}, phys={phys_state})",
                })

            # Check LID assignment
            lid = port.get("lid")
            if lid in (None, "0", "0x0", "0x0000") and state == "ACTIVE":
                issues.append({
                    "severity": "WARNING",
                    "type": "no_lid",
                    "device": device_name,
                    "port": port_num,
                    "message": f"Port {port_id} is ACTIVE but has no LID assigned",
                })

            # Check SM LID
            sm_lid = port.get("sm_lid")
            if sm_lid in (None, "0", "0x0", "0x0000") and state == "ACTIVE":
                issues.append({
                    "severity": "WARNING",
                    "type": "no_sm_lid",
                    "device": device_name,
                    "port": port_num,
                    "message": f"Port {port_id} cannot see Subnet Manager (sm_lid=0)",
                })

            # Check error counters
            counters = port.get("counters", {})
            error_thresholds = {
                "symbol_error": 0,
                "link_error_recovery": 0,
                "link_downed": 0,
                "port_rcv_errors": 0,
                "port_xmit_discards": 10,
                "local_link_integrity_errors": 0,
            }

            for counter, threshold in error_thresholds.items():
                value = counters.get(counter, 0)
                if value > threshold:
                    severity = "ERROR" if value > 100 else "WARNING"
                    issues.append({
                        "severity": severity,
                        "type": "error_counter",
                        "device": device_name,
                        "port": port_num,
                        "counter": counter,
                        "value": value,
                        "message": f"Port {port_id} has {counter}={value}",
                    })

    # Check subnet manager status
    if sm_status:
        sm_state = sm_status.get("state", "")
        if sm_state and sm_state not in ["MASTER", "STANDBY"]:
            issues.append({
                "severity": "WARNING",
                "type": "sm_state",
                "state": sm_state,
                "message": f"Subnet Manager state is {sm_state}. Expected MASTER or STANDBY.",
            })

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor InfiniBand and RDMA health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    opts = parser.parse_args(args)

    # Check for InfiniBand sysfs
    if not context.file_exists("/sys/class/infiniband"):
        output.error("No InfiniBand devices found (/sys/class/infiniband not present)")
        return 2

    # Gather data
    devices = get_ib_devices(context)
    sm_status = check_sm_status(context)

    # If no devices found, exit with error
    if not devices:
        output.error("No InfiniBand devices found")
        return 2

    # Analyze health
    issues = analyze_health(devices, sm_status)

    # Build output data
    device_summaries = []
    for device in devices:
        for port in device.get("ports", []):
            summary: dict[str, Any] = {
                "device": device["name"],
                "port": port["port"],
                "state": port.get("state", "UNKNOWN"),
                "phys_state": port.get("phys_state", "UNKNOWN"),
                "rate": port.get("rate", "N/A"),
                "lid": port.get("lid", "N/A"),
            }
            if opts.verbose:
                summary["counters"] = port.get("counters", {})
                summary["fw_ver"] = device.get("fw_ver", "N/A")
            device_summaries.append(summary)

    output.emit({
        "ports": device_summaries,
        "sm_status": sm_status,
        "issues": issues,
        "summary": {
            "device_count": len(devices),
            "port_count": len(device_summaries),
            "error_count": sum(1 for i in issues if i["severity"] == "ERROR"),
            "warning_count": sum(1 for i in issues if i["severity"] == "WARNING"),
        },
    })

    # Set summary
    active_ports = sum(1 for p in device_summaries if p["state"] == "ACTIVE")
    output.set_summary(f"{active_ports}/{len(device_summaries)} IB ports active")

    # Determine exit code
    has_issues = any(i["severity"] in ("ERROR", "WARNING") for i in issues)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
