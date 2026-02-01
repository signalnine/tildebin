#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, fibre-channel, san, storage, connectivity]
#   requires: []
#   privilege: root
#   related: [iscsi_health, drbd_health, scsi_error_monitor]
#   brief: Monitor Fibre Channel HBA health for SAN environments

"""
Monitor Fibre Channel (FC) host bus adapter (HBA) health for SAN environments.

Checks FC HBA health by reading from /sys/class/fc_host including:
- HBA port states (online, linkdown, offline)
- Port speed and negotiated link speed
- Error counters (invalid CRC, link failures, loss of sync/signal)
- Fabric connectivity

Returns exit code 1 if any FC ports have issues or errors detected.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# FC port attributes to read
FC_HOST_ATTRS = [
    "port_state", "port_type", "port_name", "node_name",
    "speed", "supported_speeds", "fabric_name",
]

# Error counter names
FC_ERROR_COUNTERS = [
    "invalid_crc_count",
    "link_failure_count",
    "loss_of_signal_count",
    "loss_of_sync_count",
    "error_frames",
]


def get_fc_hosts(context: Context) -> list[dict[str, Any]]:
    """Get list of Fibre Channel host adapters from /sys/class/fc_host."""
    hosts = []
    fc_host_path = "/sys/class/fc_host"

    if not context.file_exists(fc_host_path):
        return hosts

    try:
        host_names = context.glob("host*", root=fc_host_path)
    except Exception:
        return hosts

    for host_path in host_names:
        host_name = host_path.split("/")[-1]
        host: dict[str, Any] = {
            "name": host_name,
            "path": host_path,
        }

        # Read host attributes
        for attr in FC_HOST_ATTRS:
            attr_path = f"{host_path}/{attr}"
            if context.file_exists(attr_path):
                try:
                    host[attr] = context.read_file(attr_path).strip()
                except Exception:
                    pass

        # Get statistics
        stats_path = f"{host_path}/statistics"
        if context.file_exists(stats_path):
            host["statistics"] = get_fc_statistics(stats_path, context)

        hosts.append(host)

    return hosts


def get_fc_statistics(stats_path: str, context: Context) -> dict[str, int]:
    """Get FC port statistics from sysfs."""
    stats: dict[str, int] = {}

    for counter in FC_ERROR_COUNTERS:
        counter_path = f"{stats_path}/{counter}"
        if context.file_exists(counter_path):
            try:
                value = context.read_file(counter_path).strip()
                if value.startswith("0x"):
                    stats[counter] = int(value, 16)
                else:
                    stats[counter] = int(value)
            except (ValueError, Exception):
                pass

    return stats


def analyze_health(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze Fibre Channel health and generate issues list."""
    issues: list[dict[str, Any]] = []

    if not hosts:
        issues.append({
            "severity": "ERROR",
            "type": "no_hosts",
            "message": "No Fibre Channel HBAs found. Check if FC kernel modules are loaded.",
        })
        return issues

    for host in hosts:
        host_name = host["name"]

        # Check port state
        port_state = host.get("port_state", "Unknown")
        if port_state != "Online":
            severity = "WARNING" if port_state in ["Linkdown", "Offline"] else "ERROR"
            issues.append({
                "severity": severity,
                "type": "port_not_online",
                "host": host_name,
                "port_state": port_state,
                "message": f"{host_name}: Port state is {port_state} (expected Online)",
            })

        # Check speed
        speed = host.get("speed", "Unknown")
        if speed in ("Unknown", "unknown") and port_state == "Online":
            issues.append({
                "severity": "WARNING",
                "type": "speed_unknown",
                "host": host_name,
                "message": f"{host_name}: Port is Online but speed is unknown",
            })

        # Check fabric connectivity
        fabric_name = host.get("fabric_name", "")
        if port_state == "Online" and (not fabric_name or fabric_name == "0x0"):
            issues.append({
                "severity": "WARNING",
                "type": "no_fabric",
                "host": host_name,
                "message": f"{host_name}: Port is Online but not logged into fabric",
            })

        # Analyze error counters
        stats = host.get("statistics", {})
        error_thresholds = {
            "invalid_crc_count": (0, "CRC errors indicate cable/SFP issues"),
            "link_failure_count": (0, "Link failures indicate physical connectivity problems"),
            "loss_of_signal_count": (0, "Signal loss indicates cable/SFP/distance issues"),
            "loss_of_sync_count": (0, "Sync loss indicates speed negotiation or cable issues"),
            "error_frames": (0, "Error frames indicate protocol-level issues"),
        }

        for counter, (threshold, hint) in error_thresholds.items():
            value = stats.get(counter, 0)
            if isinstance(value, int) and value > threshold:
                severity = "ERROR" if value > 100 else "WARNING"
                issues.append({
                    "severity": severity,
                    "type": "error_counter",
                    "host": host_name,
                    "counter": counter,
                    "value": value,
                    "message": f"{host_name}: {counter}={value}. {hint}",
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
    parser = argparse.ArgumentParser(description="Monitor Fibre Channel HBA health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    opts = parser.parse_args(args)

    # Check for FC sysfs
    if not context.file_exists("/sys/class/fc_host"):
        output.error("No Fibre Channel HBAs found (/sys/class/fc_host not present)")
        return 2

    # Gather data
    hosts = get_fc_hosts(context)

    # If no hosts found, exit with error
    if not hosts:
        output.error("No Fibre Channel HBAs found")
        return 2

    # Analyze health
    issues = analyze_health(hosts)

    # Build output data
    host_summaries = []
    for host in hosts:
        summary: dict[str, Any] = {
            "name": host["name"],
            "port_state": host.get("port_state", "Unknown"),
            "speed": host.get("speed", "Unknown"),
            "port_name": host.get("port_name", "N/A"),
        }
        if opts.verbose:
            summary["fabric_name"] = host.get("fabric_name", "N/A")
            summary["statistics"] = host.get("statistics", {})
        host_summaries.append(summary)

    output.emit({
        "hosts": host_summaries,
        "issues": issues,
        "summary": {
            "host_count": len(hosts),
            "error_count": sum(1 for i in issues if i["severity"] == "ERROR"),
            "warning_count": sum(1 for i in issues if i["severity"] == "WARNING"),
        },
    })

    # Set summary
    healthy = len(hosts) - len(set(i.get("host", "") for i in issues if i.get("host")))
    output.set_summary(f"{healthy}/{len(hosts)} FC ports healthy")

    # Determine exit code
    has_issues = any(i["severity"] in ("ERROR", "WARNING") for i in issues)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
