#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, ceph, distributed, storage, cluster]
#   requires: [ceph]
#   privilege: root
#   related: [zfs_health, btrfs_health, disk_health]
#   brief: Monitor Ceph cluster health including OSDs, pools, and PGs

"""
Monitor Ceph cluster health.

Monitors Ceph distributed storage cluster for health issues including:
- Overall cluster health status (HEALTH_OK, HEALTH_WARN, HEALTH_ERR)
- OSD status and capacity
- Pool utilization
- Placement group (PG) states
- Monitor quorum

Returns exit code 0 if healthy, 1 if issues found, 2 on error.
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def run_ceph_command(cmd_args: list[str], context: Context) -> tuple[dict | None, str | None]:
    """Execute a ceph command and return parsed JSON output."""
    try:
        cmd = ["ceph"] + cmd_args + ["--format", "json"]
        result = context.run(cmd, check=False)
        if result.returncode != 0:
            return None, result.stderr
        return json.loads(result.stdout), None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse JSON: {e}"
    except Exception as e:
        return None, str(e)


def get_cluster_status(context: Context) -> tuple[dict | None, str | None]:
    """Get overall cluster status."""
    return run_ceph_command(["status"], context)


def get_osd_tree(context: Context) -> tuple[dict | None, str | None]:
    """Get OSD tree structure."""
    return run_ceph_command(["osd", "tree"], context)


def get_osd_df(context: Context) -> tuple[dict | None, str | None]:
    """Get OSD disk usage."""
    return run_ceph_command(["osd", "df"], context)


def get_pool_stats(context: Context) -> tuple[dict | None, str | None]:
    """Get pool statistics."""
    return run_ceph_command(["df", "detail"], context)


def analyze_cluster_health(status: dict) -> dict[str, Any]:
    """Analyze cluster health from status output."""
    health_info = {
        "status": "unknown",
        "checks": [],
        "messages": [],
    }

    if not status:
        return health_info

    health = status.get("health", {})
    health_info["status"] = health.get("status", "unknown")

    # Extract health checks
    checks = health.get("checks", {})
    for check_name, check_data in checks.items():
        severity = check_data.get("severity", "unknown")
        summary = check_data.get("summary", {}).get("message", "")
        health_info["checks"].append({
            "name": check_name,
            "severity": severity,
            "message": summary,
        })

    return health_info


def analyze_osd_health(osd_tree: dict | None, osd_df: dict | None) -> dict[str, Any]:
    """Analyze OSD health and capacity."""
    osd_info = {
        "total": 0,
        "up": 0,
        "down": 0,
        "in": 0,
        "out": 0,
        "osds": [],
        "warnings": [],
    }

    if not osd_tree:
        return osd_info

    nodes = osd_tree.get("nodes", [])
    for node in nodes:
        if node.get("type") == "osd":
            osd_id = node.get("id", -1)
            is_up = node.get("status", "") == "up"
            is_in = node.get("reweight", 0) > 0

            osd_info["total"] += 1
            if is_up:
                osd_info["up"] += 1
            else:
                osd_info["down"] += 1
            if is_in:
                osd_info["in"] += 1
            else:
                osd_info["out"] += 1

            osd_entry = {
                "id": osd_id,
                "name": node.get("name", f"osd.{osd_id}"),
                "status": "up" if is_up else "down",
                "in_cluster": is_in,
            }

            # Add capacity info from osd_df if available
            if osd_df:
                osd_nodes = osd_df.get("nodes", [])
                for df_node in osd_nodes:
                    if df_node.get("id") == osd_id:
                        osd_entry["utilization"] = df_node.get("utilization", 0)
                        osd_entry["pgs"] = df_node.get("pgs", 0)
                        break

            osd_info["osds"].append(osd_entry)

            # Check for issues
            if not is_up:
                osd_info["warnings"].append(f"OSD {osd_id} is DOWN")
            if not is_in and is_up:
                osd_info["warnings"].append(f"OSD {osd_id} is UP but OUT")
            if osd_entry.get("utilization", 0) > 85:
                osd_info["warnings"].append(
                    f"OSD {osd_id} utilization is high: {osd_entry['utilization']:.1f}%"
                )

    return osd_info


def analyze_pool_health(pool_stats: dict | None) -> dict[str, Any]:
    """Analyze pool utilization and health."""
    pool_info = {
        "pools": [],
        "total_capacity": 0,
        "used_capacity": 0,
        "warnings": [],
    }

    if not pool_stats:
        return pool_info

    stats = pool_stats.get("stats", {})
    pool_info["total_capacity"] = stats.get("total_bytes", 0)
    pool_info["used_capacity"] = stats.get("total_used_bytes", 0)

    pools = pool_stats.get("pools", [])
    for pool in pools:
        pool_name = pool.get("name", "unknown")
        pool_stats_data = pool.get("stats", {})

        pool_entry = {
            "name": pool_name,
            "id": pool.get("id", -1),
            "stored": pool_stats_data.get("stored", 0),
            "objects": pool_stats_data.get("objects", 0),
            "percent_used": pool_stats_data.get("percent_used", 0) * 100,
        }

        pool_info["pools"].append(pool_entry)

        if pool_entry["percent_used"] > 80:
            pool_info["warnings"].append(
                f"Pool '{pool_name}' utilization is high: {pool_entry['percent_used']:.1f}%"
            )

    return pool_info


def analyze_pg_status(status: dict | None) -> dict[str, Any]:
    """Analyze placement group status from cluster status."""
    pg_info = {
        "total": 0,
        "active_clean": 0,
        "degraded": 0,
        "recovering": 0,
        "undersized": 0,
        "stale": 0,
        "warnings": [],
    }

    if not status:
        return pg_info

    pgmap = status.get("pgmap", {})
    pg_info["total"] = pgmap.get("num_pgs", 0)

    pgs_by_state = pgmap.get("pgs_by_state", [])
    for state_entry in pgs_by_state:
        state_name = state_entry.get("state_name", "")
        count = state_entry.get("count", 0)

        if state_name == "active+clean":
            pg_info["active_clean"] = count
        elif "degraded" in state_name:
            pg_info["degraded"] += count
        elif "recovering" in state_name or "backfilling" in state_name:
            pg_info["recovering"] += count
        elif "undersized" in state_name:
            pg_info["undersized"] += count
        elif "stale" in state_name:
            pg_info["stale"] += count

    if pg_info["degraded"] > 0:
        pg_info["warnings"].append(f"{pg_info['degraded']} PGs are degraded")
    if pg_info["stale"] > 0:
        pg_info["warnings"].append(f"{pg_info['stale']} PGs are stale")
    if pg_info["undersized"] > 0:
        pg_info["warnings"].append(f"{pg_info['undersized']} PGs are undersized")

    return pg_info


def analyze_monitor_status(status: dict | None) -> dict[str, Any]:
    """Analyze monitor quorum status."""
    mon_info = {
        "total": 0,
        "in_quorum": 0,
        "quorum_names": [],
        "warnings": [],
    }

    if not status:
        return mon_info

    monmap = status.get("monmap", {})
    mon_info["total"] = monmap.get("num_mons", 0)

    quorum = status.get("quorum", [])
    quorum_names = status.get("quorum_names", [])
    mon_info["in_quorum"] = len(quorum)
    mon_info["quorum_names"] = quorum_names

    if mon_info["in_quorum"] < mon_info["total"]:
        out_of_quorum = mon_info["total"] - mon_info["in_quorum"]
        mon_info["warnings"].append(f"{out_of_quorum} monitors out of quorum")

    return mon_info


def format_bytes(size_bytes: int) -> str:
    """Format bytes to human readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} EB"


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
    parser = argparse.ArgumentParser(description="Monitor Ceph cluster health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for ceph tool
    if not context.check_tool("ceph"):
        output.error("ceph not found. Install ceph-common package.")
        return 2

    # Gather cluster information
    status, error = get_cluster_status(context)
    if error:
        output.error(f"Failed to get cluster status: {error}")
        return 2

    osd_tree, _ = get_osd_tree(context)
    osd_df, _ = get_osd_df(context)
    pool_stats, _ = get_pool_stats(context)

    # Analyze data
    health = analyze_cluster_health(status)
    osds = analyze_osd_health(osd_tree, osd_df)
    pools = analyze_pool_health(pool_stats)
    pgs = analyze_pg_status(status)
    monitors = analyze_monitor_status(status)

    # Collect all warnings
    all_warnings = (
        [(c["name"], c["message"]) for c in health["checks"]]
        + [("OSD", w) for w in osds["warnings"]]
        + [("Pool", w) for w in pools["warnings"]]
        + [("PG", w) for w in pgs["warnings"]]
        + [("Monitor", w) for w in monitors["warnings"]]
    )

    # Build result
    result = {
        "health": health,
        "osds": {
            "total": osds["total"],
            "up": osds["up"],
            "down": osds["down"],
            "in": osds["in"],
            "out": osds["out"],
        },
        "pgs": {
            "total": pgs["total"],
            "active_clean": pgs["active_clean"],
            "degraded": pgs["degraded"],
        },
        "monitors": {
            "total": monitors["total"],
            "in_quorum": monitors["in_quorum"],
        },
        "warnings": [{"source": src, "message": msg} for src, msg in all_warnings],
    }

    if opts.verbose:
        result["osds"]["details"] = osds["osds"]
        result["pools"] = pools
        result["monitors"]["quorum_names"] = monitors["quorum_names"]

    output.emit(result)

    # Set summary
    output.set_summary(
        f"Cluster {health['status']}, {osds['up']}/{osds['total']} OSDs up, "
        f"{len(all_warnings)} warnings"
    )

    # Log warnings
    for source, message in all_warnings:
        output.warning(f"[{source}] {message}")

    # Determine exit code
    is_healthy = health["status"] == "HEALTH_OK"
    return 0 if is_healthy else 1


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
