#!/usr/bin/env python3
# boxctl:
#   category: baremetal/numa
#   tags: [health, numa, memory, performance]
#   related: [numa_topology_analyzer, memory_usage]
#   brief: Monitor NUMA memory balance across nodes

"""
Monitor NUMA memory balance across nodes.

Analyzes NUMA node memory distribution and detects imbalances that can cause
performance degradation on multi-socket systems. NUMA-aware workload placement
is critical for optimal performance on large baremetal servers.

Checks performed:
- NUMA node memory usage and availability
- Cross-node memory imbalance detection
- Per-node free memory warnings
- NUMA statistics (hits, misses, foreign allocations)

Exit codes:
    0: All NUMA nodes are balanced
    1: NUMA imbalance detected or memory pressure warnings
    2: Usage error or non-NUMA system
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_meminfo(content: str, node_id: int) -> dict:
    """
    Parse NUMA node meminfo file.

    Returns dict with memory values in KB.
    """
    meminfo = {}
    prefix = f"Node {node_id} "

    for line in content.strip().split("\n"):
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value_parts = value.strip().split()
        if value_parts:
            try:
                meminfo[key.replace(prefix, "")] = int(value_parts[0])
            except ValueError:
                pass

    return meminfo


def parse_numastat(content: str) -> dict:
    """Parse NUMA statistics file."""
    stats = {}
    for line in content.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            try:
                stats[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return stats


def parse_cpulist(content: str) -> list[int]:
    """Parse CPU list string (e.g., '0-3,8-11') into list of CPU IDs."""
    cpus = []
    if not content.strip():
        return cpus

    for part in content.strip().split(","):
        if "-" in part:
            start, end = part.split("-")
            cpus.extend(range(int(start), int(end) + 1))
        else:
            cpus.append(int(part))
    return cpus


def format_bytes(kb: int) -> str:
    """Convert KB to human-readable format."""
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb / 1024 / 1024:.1f} GB"


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
    parser = argparse.ArgumentParser(
        description="Monitor NUMA topology and memory balance"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed per-node info")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show output if issues detected"
    )
    parser.add_argument(
        "--imbalance",
        type=float,
        default=20.0,
        help="Imbalance threshold percentage (default: 20)",
    )
    parser.add_argument(
        "--free-warn",
        type=float,
        default=10.0,
        help="Warn when free memory falls below this %% (default: 10)",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if not 0.0 <= opts.imbalance <= 100.0:
        output.error("Imbalance threshold must be between 0 and 100")
        return 2

    if not 0.0 <= opts.free_warn <= 100.0:
        output.error("Free memory warning threshold must be between 0 and 100")
        return 2

    # Check for NUMA availability
    if not context.file_exists("/sys/devices/system/node"):
        output.error("NUMA topology not available at /sys/devices/system/node")
        return 2

    # Find NUMA nodes
    node_dirs = context.glob("node[0-9]*", "/sys/devices/system/node")
    if not node_dirs:
        output.error("No NUMA nodes found")
        return 2

    # Extract node IDs and sort
    node_ids = []
    for path in node_dirs:
        parts = path.split("/")
        node_name = parts[-1] if parts[-1].startswith("node") else None
        if node_name and node_name[4:].isdigit():
            node_ids.append(int(node_name[4:]))
    node_ids = sorted(node_ids)

    if len(node_ids) < 2:
        output.error("Only one NUMA node found - NUMA balancing not applicable")
        return 2

    # Collect node information
    nodes = []
    for node_id in node_ids:
        base_path = f"/sys/devices/system/node/node{node_id}"

        node_info = {
            "node_id": node_id,
            "cpus": [],
            "memory": {},
            "numastat": {},
            "status": "OK",
            "issues": [],
        }

        # Read CPU list
        try:
            cpulist = context.read_file(f"{base_path}/cpulist")
            node_info["cpus"] = parse_cpulist(cpulist)
        except (FileNotFoundError, IOError):
            pass

        # Read memory info
        try:
            meminfo = context.read_file(f"{base_path}/meminfo")
            node_info["memory"] = parse_meminfo(meminfo, node_id)
        except (FileNotFoundError, IOError):
            pass

        # Calculate derived values
        total = node_info["memory"].get("MemTotal", 0)
        free = node_info["memory"].get("MemFree", 0)
        if total > 0:
            node_info["memory"]["MemUsed"] = total - free
            node_info["memory"]["used_percent"] = ((total - free) / total) * 100
            node_info["memory"]["free_percent"] = (free / total) * 100

        # Read NUMA stats
        try:
            numastat = context.read_file(f"{base_path}/numastat")
            node_info["numastat"] = parse_numastat(numastat)
        except (FileNotFoundError, IOError):
            pass

        nodes.append(node_info)

    # Analyze balance
    issues = []
    usage_percents = []
    total_memory = 0
    total_used = 0

    for node in nodes:
        mem = node["memory"]
        if "used_percent" in mem:
            usage_percents.append(mem["used_percent"])
        if "MemTotal" in mem:
            total_memory += mem["MemTotal"]
        if "MemUsed" in mem:
            total_used += mem["MemUsed"]

    avg_usage = sum(usage_percents) / len(usage_percents) if usage_percents else 0

    for node in nodes:
        mem = node["memory"]
        node_id = node["node_id"]

        # Check memory imbalance
        if "used_percent" in mem:
            deviation = abs(mem["used_percent"] - avg_usage)
            if deviation > opts.imbalance:
                node["status"] = "WARNING"
                issues.append({
                    "type": "memory_imbalance",
                    "node": node_id,
                    "usage_percent": mem["used_percent"],
                    "avg_usage_percent": avg_usage,
                    "deviation": deviation,
                })
                node["issues"].append(
                    f"Memory imbalance: {mem['used_percent']:.1f}% used vs {avg_usage:.1f}% average"
                )

        # Check low free memory
        if "free_percent" in mem:
            if mem["free_percent"] < opts.free_warn:
                if node["status"] == "OK":
                    node["status"] = "WARNING"
                issues.append({
                    "type": "low_free_memory",
                    "node": node_id,
                    "free_percent": mem["free_percent"],
                    "free_kb": mem.get("MemFree", 0),
                })
                node["issues"].append(f"Low free memory: {mem['free_percent']:.1f}% free")

        # Check NUMA statistics
        numastat = node["numastat"]
        if numastat:
            numa_miss = numastat.get("numa_miss", 0)
            numa_hit = numastat.get("numa_hit", 0)

            total_allocs = numa_hit + numa_miss
            if total_allocs > 1000:
                miss_ratio = numa_miss / total_allocs if total_allocs > 0 else 0
                if miss_ratio > 0.1:  # More than 10% misses
                    if node["status"] == "OK":
                        node["status"] = "WARNING"
                    issues.append({
                        "type": "high_numa_miss",
                        "node": node_id,
                        "numa_hit": numa_hit,
                        "numa_miss": numa_miss,
                        "miss_ratio": miss_ratio * 100,
                    })
                    node["issues"].append(
                        f"High NUMA miss ratio: {miss_ratio * 100:.1f}% ({numa_miss} misses)"
                    )

    summary = {
        "node_count": len(nodes),
        "total_memory_kb": total_memory,
        "total_used_kb": total_used,
        "avg_usage_percent": avg_usage,
        "max_usage_percent": max(usage_percents) if usage_percents else 0,
        "min_usage_percent": min(usage_percents) if usage_percents else 0,
        "issue_count": len(issues),
    }

    # Build result
    result = {
        "summary": summary,
        "nodes": nodes,
        "issues": issues,
        "status": "healthy" if not issues else "warning",
    }

    # Output
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or issues:
            lines = []
            lines.append(f"NUMA Nodes: {summary['node_count']}")
            lines.append(f"Total Memory: {format_bytes(summary['total_memory_kb'])}")
            lines.append(f"Average Usage: {summary['avg_usage_percent']:.1f}%")
            lines.append("")

            if issues:
                lines.append(f"Found {len(issues)} NUMA balance issues:")
                lines.append("")
                for issue in issues:
                    if issue["type"] == "memory_imbalance":
                        lines.append(
                            f"[WARNING] Node {issue['node']}: Memory imbalance - "
                            f"{issue['usage_percent']:.1f}% used vs "
                            f"{issue['avg_usage_percent']:.1f}% average "
                            f"(deviation: {issue['deviation']:.1f}%)"
                        )
                    elif issue["type"] == "low_free_memory":
                        lines.append(
                            f"[WARNING] Node {issue['node']}: Low free memory - "
                            f"{issue['free_percent']:.1f}% free ({format_bytes(issue['free_kb'])})"
                        )
                    elif issue["type"] == "high_numa_miss":
                        lines.append(
                            f"[WARNING] Node {issue['node']}: High NUMA miss ratio - "
                            f"{issue['miss_ratio']:.1f}% (hits: {issue['numa_hit']}, "
                            f"misses: {issue['numa_miss']})"
                        )
            else:
                lines.append("[OK] No NUMA balance issues detected")

            if opts.verbose:
                lines.append("")
                lines.append("Per-Node Details:")
                for node in nodes:
                    mem = node["memory"]
                    lines.append(f"  Node {node['node_id']}:")
                    cpu_range = (
                        f"{node['cpus'][0]}-{node['cpus'][-1]}"
                        if node["cpus"]
                        else "none"
                    )
                    lines.append(f"    CPUs: {len(node['cpus'])} ({cpu_range})")
                    if "MemTotal" in mem:
                        lines.append(
                            f"    Memory: {format_bytes(mem.get('MemUsed', 0))} / "
                            f"{format_bytes(mem['MemTotal'])} "
                            f"({mem.get('used_percent', 0):.1f}% used)"
                        )
                    if node["numastat"]:
                        stats = node["numastat"]
                        lines.append(
                            f"    NUMA stats: hits={stats.get('numa_hit', 0)}, "
                            f"misses={stats.get('numa_miss', 0)}, "
                            f"foreign={stats.get('numa_foreign', 0)}"
                        )

            print("\n".join(lines))

    # Set summary
    status = "healthy" if not issues else "warning"
    output.set_summary(f"nodes={len(nodes)}, issues={len(issues)}, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
