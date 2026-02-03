#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, iscsi, san, storage, connectivity]
#   requires: [iscsiadm]
#   privilege: root
#   related: [fc_health, drbd_health, scsi_error_monitor]
#   brief: Monitor iSCSI session health and connectivity

"""
Monitor iSCSI session health and connectivity on baremetal servers.

Checks iSCSI initiator health including:
- Active iSCSI sessions and their state
- Target connectivity and availability
- Session error counts and recovery events
- Attached SCSI devices

Returns exit code 1 if any sessions have issues or errors detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_iscsi_sessions(context: Context) -> list[dict[str, Any]] | None:
    """Get list of active iSCSI sessions."""
    result = context.run(["iscsiadm", "-m", "session"], check=False)

    if result.returncode != 0:
        if "No active sessions" in result.stderr:
            return []
        return None

    sessions = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue

        # Parse session line: transport: [sid] ip:port,tpgt targetname
        # Example: tcp: [1] 192.168.1.100:3260,1 iqn.2023-01.com.example:target1
        match = re.match(r"(\w+):\s+\[(\d+)\]\s+([\d.]+):(\d+),(\d+)\s+(.+)", line)
        if match:
            sessions.append({
                "transport": match.group(1),
                "sid": match.group(2),
                "portal_ip": match.group(3),
                "portal_port": match.group(4),
                "tpgt": match.group(5),
                "target": match.group(6),
            })

    return sessions


def get_session_details(sid: str, context: Context) -> dict[str, Any]:
    """Get detailed information for a specific session."""
    result = context.run(["iscsiadm", "-m", "session", "-r", sid, "-P", "3"], check=False)

    if result.returncode != 0:
        return {}

    details: dict[str, Any] = {
        "state": "unknown",
        "connection_state": "unknown",
        "devices": [],
    }

    for line in result.stdout.split("\n"):
        line = line.strip()

        # Session state
        if "iSCSI Session State:" in line:
            details["state"] = line.split(":")[1].strip()
        elif "iSCSI Connection State:" in line:
            details["connection_state"] = line.split(":")[1].strip()

        # Device info
        if "Attached scsi disk" in line:
            match = re.search(r"Attached scsi disk\s+(\w+)\s+State:\s+(\w+)", line)
            if match:
                details["devices"].append({
                    "name": match.group(1),
                    "state": match.group(2),
                })

    return details


def get_session_stats(sid: str, context: Context) -> dict[str, int]:
    """Get session statistics (error counts)."""
    result = context.run(["iscsiadm", "-m", "session", "-r", sid, "-s"], check=False)

    if result.returncode != 0:
        return {}

    stats: dict[str, int] = {
        "txdata_octets": 0,
        "rxdata_octets": 0,
        "timeout_errors": 0,
        "digest_errors": 0,
    }

    for line in result.stdout.split("\n"):
        line = line.strip()

        if "txdata_octets:" in line:
            match = re.search(r"txdata_octets:\s*(\d+)", line)
            if match:
                stats["txdata_octets"] = int(match.group(1))
        elif "rxdata_octets:" in line:
            match = re.search(r"rxdata_octets:\s*(\d+)", line)
            if match:
                stats["rxdata_octets"] = int(match.group(1))
        elif "timeout_err:" in line:
            match = re.search(r"timeout_err:\s*(\d+)", line)
            if match:
                stats["timeout_errors"] = int(match.group(1))
        elif "digest_err:" in line:
            match = re.search(r"digest_err:\s*(\d+)", line)
            if match:
                stats["digest_errors"] = int(match.group(1))

    return stats


def analyze_session(
    session: dict[str, Any],
    details: dict[str, Any],
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """Analyze a session and return issues found."""
    issues = []
    target = session["target"]

    # Check session state
    if details.get("state") and details["state"] != "LOGGED_IN":
        issues.append({
            "severity": "CRITICAL",
            "component": "session",
            "target": target,
            "message": f"Session not logged in (state: {details['state']})",
        })

    # Check connection state
    if details.get("connection_state") and details["connection_state"] != "LOGGED_IN":
        issues.append({
            "severity": "WARNING",
            "component": "connection",
            "target": target,
            "message": f"Connection degraded (state: {details['connection_state']})",
        })

    # Check attached devices
    for device in details.get("devices", []):
        if device["state"] != "running":
            issues.append({
                "severity": "WARNING",
                "component": "device",
                "target": target,
                "device": device["name"],
                "message": f"Device {device['name']} not running (state: {device['state']})",
            })

    # Check stats for errors
    if stats.get("timeout_errors", 0) > 0:
        issues.append({
            "severity": "WARNING",
            "component": "stats",
            "target": target,
            "message": f"Timeout errors: {stats['timeout_errors']}",
        })
    if stats.get("digest_errors", 0) > 0:
        issues.append({
            "severity": "WARNING",
            "component": "stats",
            "target": target,
            "message": f"Digest errors: {stats['digest_errors']}",
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
    parser = argparse.ArgumentParser(description="Monitor iSCSI session health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    opts = parser.parse_args(args)

    # Check for iscsiadm
    if not context.check_tool("iscsiadm"):
        output.error("iscsiadm not found. Install open-iscsi package.")

        output.render(opts.format, "Monitor iSCSI session health and connectivity")
        return 2

    # Get sessions
    sessions = get_iscsi_sessions(context)
    if sessions is None:
        output.error("Failed to get iSCSI sessions")

        output.render(opts.format, "Monitor iSCSI session health and connectivity")
        return 2

    if not sessions:
        output.emit({"sessions": [], "issues": []})
        output.set_summary("No active iSCSI sessions")

        output.render(opts.format, "Monitor iSCSI session health and connectivity")
        return 0

    # Analyze each session
    session_results = []
    all_issues: list[dict[str, Any]] = []

    for session in sessions:
        details = get_session_details(session["sid"], context)
        stats = get_session_stats(session["sid"], context)
        issues = analyze_session(session, details, stats)

        session_info: dict[str, Any] = {
            "target": session["target"],
            "portal": f"{session['portal_ip']}:{session['portal_port']}",
            "state": details.get("state", "unknown"),
            "devices": [d["name"] for d in details.get("devices", [])],
        }

        if opts.verbose:
            session_info["stats"] = stats
            session_info["issues"] = issues

        session_results.append(session_info)
        all_issues.extend(issues)

    output.emit({
        "sessions": session_results,
        "issues": all_issues,
        "summary": {
            "total_sessions": len(sessions),
            "sessions_with_issues": len(set(i["target"] for i in all_issues)),
        },
    })

    # Set summary
    healthy = len(sessions) - len(set(i["target"] for i in all_issues))
    output.set_summary(f"{healthy}/{len(sessions)} sessions healthy")


    output.render(opts.format, "Monitor iSCSI session health and connectivity")
    return 1 if all_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
