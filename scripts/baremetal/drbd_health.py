#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, drbd, replication, storage, ha]
#   requires: [drbdadm]
#   privilege: root
#   related: [iscsi_health, fc_health, lvm_health]
#   brief: Monitor DRBD replication health and synchronization status

"""
Monitor DRBD (Distributed Replicated Block Device) replication health.

Checks DRBD resources for synchronization issues including:
- Connection state (Connected, StandAlone, etc.)
- Disk states (UpToDate, Inconsistent, etc.)
- Role configuration (Primary/Secondary)
- Split-brain detection
- Synchronization progress

Returns exit code 1 if any DRBD resources have issues.
"""

import argparse
import json
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_drbd_status_json(context: Context) -> list[dict[str, Any]] | None:
    """Get DRBD status using drbdsetup (DRBD 9+)."""
    result = context.run(["drbdsetup", "status", "--json"], check=False)
    if result.returncode == 0 and result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


def get_drbd_status_text(context: Context) -> str | None:
    """Get DRBD status using drbdadm status."""
    result = context.run(["drbdadm", "status"], check=False)
    if result.returncode == 0:
        return result.stdout
    return None


def parse_drbdadm_status(status_text: str) -> list[dict[str, Any]]:
    """Parse drbdadm status output into structured data."""
    resources: list[dict[str, Any]] = []

    if not status_text:
        return resources

    current_resource: dict[str, Any] | None = None

    for line in status_text.split("\n"):
        # Resource line: r0 role:Primary
        resource_match = re.match(r"^(\S+)\s+role:(\S+)", line)
        if resource_match:
            if current_resource:
                resources.append(current_resource)

            current_resource = {
                "name": resource_match.group(1),
                "local_role": resource_match.group(2),
                "peer_role": None,
                "local_disk_state": None,
                "peer_disk_state": None,
                "connection_state": None,
                "sync_percent": None,
            }
            continue

        if not current_resource:
            continue

        # Disk line:   disk:UpToDate
        disk_match = re.match(r"^\s+disk:(\S+)", line)
        if disk_match:
            current_resource["local_disk_state"] = disk_match.group(1)
            continue

        # Connection line:   peer connection:Connected
        conn_match = re.match(r"^\s+(\S+)\s+connection:(\S+)", line)
        if conn_match:
            current_resource["connection_state"] = conn_match.group(2)
            continue

        # Peer role:   peer role:Secondary
        peer_role_match = re.match(r"^\s+(\S+)\s+role:(\S+)", line)
        if peer_role_match:
            current_resource["peer_role"] = peer_role_match.group(2)
            continue

        # Peer disk line:     peer-disk:UpToDate
        peer_disk_match = re.match(r"^\s+peer-disk:(\S+)", line)
        if peer_disk_match:
            current_resource["peer_disk_state"] = peer_disk_match.group(1)
            continue

        # Replication state:     replication:SyncSource peer-disk:Inconsistent
        repl_match = re.match(r"^\s+(\S+)\s+replication:(\S+)", line)
        if repl_match:
            current_resource["connection_state"] = repl_match.group(2)
            # Also check for peer-disk on same line
            peer_disk_inline = re.search(r"peer-disk:(\S+)", line)
            if peer_disk_inline:
                current_resource["peer_disk_state"] = peer_disk_inline.group(1)
            # Don't continue - also check for sync progress

        # Sync progress: done:45.23
        sync_match = re.search(r"done:([\d.]+)", line)
        if sync_match:
            current_resource["sync_percent"] = float(sync_match.group(1))

    if current_resource:
        resources.append(current_resource)

    return resources


def parse_drbd_json_status(json_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse DRBD 9+ JSON status into resource list."""
    resources: list[dict[str, Any]] = []

    for res in json_data:
        resource: dict[str, Any] = {
            "name": res.get("name", "unknown"),
            "local_role": res.get("role", "Unknown"),
            "peer_role": None,
            "local_disk_state": None,
            "peer_disk_state": None,
            "connection_state": None,
            "sync_percent": None,
        }

        # Get local disk state from devices
        devices = res.get("devices", [])
        if devices:
            resource["local_disk_state"] = devices[0].get("disk-state", "Unknown")

        # Get connection and peer info
        connections = res.get("connections", [])
        for conn in connections:
            resource["connection_state"] = conn.get("connection-state", "Unknown")
            resource["peer_role"] = conn.get("peer-role", "Unknown")

            peer_devices = conn.get("peer_devices", [])
            if peer_devices:
                resource["peer_disk_state"] = peer_devices[0].get("peer-disk-state", "Unknown")

                # Get sync progress
                done = peer_devices[0].get("done")
                if done is not None:
                    resource["sync_percent"] = float(done)

            break  # Use first connection

        resources.append(resource)

    return resources


def get_drbd_resources(context: Context) -> list[dict[str, Any]]:
    """Get all DRBD resources using the best available method."""
    # Try DRBD 9+ JSON first
    json_status = get_drbd_status_json(context)
    if json_status:
        return parse_drbd_json_status(json_status)

    # Try drbdadm status
    status_text = get_drbd_status_text(context)
    if status_text:
        return parse_drbdadm_status(status_text)

    return []


def analyze_resources(
    resources: list[dict[str, Any]],
    sync_warn: float,
    sync_crit: float,
) -> list[dict[str, Any]]:
    """Analyze DRBD resources for issues."""
    issues: list[dict[str, Any]] = []

    # Connection states that indicate problems
    bad_connection_states = [
        "StandAlone", "Disconnecting", "Unconnected", "Timeout",
        "BrokenPipe", "NetworkFailure", "ProtocolError",
        "TearDown", "WFConnection", "WFReportParams",
    ]

    # Disk states that indicate problems
    bad_disk_states = [
        "Diskless", "Failed", "Inconsistent", "Outdated",
        "DUnknown", "Attaching",
    ]

    for resource in resources:
        name = resource["name"]

        # Check connection state
        conn_state = resource.get("connection_state")
        if conn_state in bad_connection_states:
            severity = "CRITICAL" if conn_state in ["StandAlone", "Disconnecting"] else "WARNING"
            issues.append({
                "severity": severity,
                "component": "connection",
                "resource": name,
                "message": f"Resource {name} connection state: {conn_state}",
            })

        # Check for split-brain (both Primary)
        if resource.get("local_role") == "Primary" and resource.get("peer_role") == "Primary":
            issues.append({
                "severity": "CRITICAL",
                "component": "role",
                "resource": name,
                "message": f"Resource {name} SPLIT-BRAIN detected! Both nodes are Primary",
            })

        # Check local disk state
        local_disk = resource.get("local_disk_state")
        if local_disk in bad_disk_states:
            is_syncing = resource.get("sync_percent") is not None
            if local_disk == "Inconsistent" and is_syncing:
                issues.append({
                    "severity": "INFO",
                    "component": "disk",
                    "resource": name,
                    "message": f"Resource {name} local disk syncing ({resource['sync_percent']:.1f}% complete)",
                })
            else:
                severity = "CRITICAL" if local_disk in ["Failed", "Diskless"] else "WARNING"
                issues.append({
                    "severity": severity,
                    "component": "disk",
                    "resource": name,
                    "message": f"Resource {name} local disk state: {local_disk}",
                })

        # Check peer disk state
        peer_disk = resource.get("peer_disk_state")
        if peer_disk and peer_disk in bad_disk_states:
            is_syncing = resource.get("sync_percent") is not None
            if not (peer_disk == "Inconsistent" and is_syncing):
                severity = "CRITICAL" if peer_disk in ["Failed", "Diskless"] else "WARNING"
                issues.append({
                    "severity": severity,
                    "component": "disk",
                    "resource": name,
                    "message": f"Resource {name} peer disk state: {peer_disk}",
                })

        # Check sync progress thresholds
        sync_percent = resource.get("sync_percent")
        if sync_percent is not None:
            if sync_percent < sync_crit:
                issues.append({
                    "severity": "CRITICAL",
                    "component": "sync",
                    "resource": name,
                    "message": f"Resource {name} sync critically low: {sync_percent:.1f}%",
                })
            elif sync_percent < sync_warn:
                issues.append({
                    "severity": "WARNING",
                    "component": "sync",
                    "resource": name,
                    "message": f"Resource {name} sync progress: {sync_percent:.1f}%",
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
    parser = argparse.ArgumentParser(description="Monitor DRBD replication health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    parser.add_argument("--sync-warn", type=float, default=90.0, help="Sync warning threshold")
    parser.add_argument("--sync-crit", type=float, default=50.0, help="Sync critical threshold")
    opts = parser.parse_args(args)

    # Check for drbdadm
    if not context.check_tool("drbdadm"):
        output.error("drbdadm not found. Install drbd-utils package.")

        output.render(opts.format, "Monitor DRBD replication health and synchronization status")
        return 2

    # Get DRBD resources
    resources = get_drbd_resources(context)

    if not resources:
        output.emit({"resources": [], "issues": []})
        output.set_summary("No DRBD resources configured")

        output.render(opts.format, "Monitor DRBD replication health and synchronization status")
        return 0

    # Analyze for issues
    issues = analyze_resources(resources, opts.sync_warn, opts.sync_crit)

    # Build output data
    resource_summaries = []
    for res in resources:
        summary: dict[str, Any] = {
            "name": res["name"],
            "role": f"{res.get('local_role', '?')}/{res.get('peer_role', '?')}",
            "disk_state": f"{res.get('local_disk_state', '?')}/{res.get('peer_disk_state', '?')}",
            "connection": res.get("connection_state", "Unknown"),
        }
        if res.get("sync_percent") is not None:
            summary["sync_percent"] = res["sync_percent"]
        resource_summaries.append(summary)

    output.emit({
        "resources": resource_summaries,
        "issues": issues,
        "summary": {
            "resource_count": len(resources),
            "healthy": sum(1 for r in resources
                         if r.get("local_disk_state") == "UpToDate"
                         and r.get("connection_state") in ["Connected", None]),
        },
    })

    # Set summary
    healthy = sum(1 for r in resources if r.get("local_disk_state") == "UpToDate")
    output.set_summary(f"{healthy}/{len(resources)} resources healthy")

    # Determine exit code (only CRITICAL and WARNING count)
    has_issues = any(i["severity"] in ("CRITICAL", "WARNING") for i in issues)

    output.render(opts.format, "Monitor DRBD replication health and synchronization status")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
