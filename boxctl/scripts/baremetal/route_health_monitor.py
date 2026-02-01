#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, routing, gateway, connectivity]
#   requires: [ip]
#   brief: Monitor network routing health and gateway reachability

"""
Monitor network routing health including default gateway reachability.

Checks routing table consistency, default gateway availability, and
detects routing issues that could cause connectivity problems.

Exit codes:
    0 - All routes healthy, gateway reachable
    1 - Routing issues detected (unreachable gateway, missing routes)
    2 - Usage error or missing dependency
"""

import argparse
import json
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_route_line(line: str, ip_version: str) -> dict[str, Any] | None:
    """Parse a route line from ip route output."""
    if not line.strip():
        return None

    parts = line.split()
    if not parts:
        return None

    route: dict[str, Any] = {
        "destination": parts[0],
        "gateway": None,
        "interface": None,
        "metric": None,
        "scope": None,
        "ip_version": ip_version,
        "raw": line.strip(),
    }

    # Parse gateway (via X.X.X.X)
    via_match = re.search(r"via\s+(\S+)", line)
    if via_match:
        route["gateway"] = via_match.group(1)

    # Parse interface (dev ethX)
    dev_match = re.search(r"dev\s+(\S+)", line)
    if dev_match:
        route["interface"] = dev_match.group(1)

    # Parse metric
    metric_match = re.search(r"metric\s+(\d+)", line)
    if metric_match:
        route["metric"] = int(metric_match.group(1))

    # Parse scope
    scope_match = re.search(r"scope\s+(\S+)", line)
    if scope_match:
        route["scope"] = scope_match.group(1)

    return route


def get_default_routes(context: Context) -> list[dict]:
    """Get all default routes from routing table."""
    routes = []

    # Get IPv4 default routes
    try:
        result = context.run(["ip", "-4", "route", "show", "default"])
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                route = parse_route_line(line, "ipv4")
                if route:
                    routes.append(route)
    except Exception:
        pass

    # Get IPv6 default routes
    try:
        result = context.run(["ip", "-6", "route", "show", "default"])
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                route = parse_route_line(line, "ipv6")
                if route:
                    routes.append(route)
    except Exception:
        pass

    return routes


def get_all_routes(context: Context) -> list[dict]:
    """Get all routes from routing table."""
    routes = []
    try:
        result = context.run(["ip", "-4", "route", "show"])
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    route = parse_route_line(line, "ipv4")
                    if route:
                        routes.append(route)
    except Exception:
        pass
    return routes


def ping_gateway(gateway: str, count: int, timeout: int, context: Context) -> dict:
    """Ping a gateway to check reachability."""
    is_ipv6 = ":" in gateway
    cmd = ["ping6" if is_ipv6 else "ping", "-c", str(count), "-W", str(timeout), gateway]

    result_info: dict[str, Any] = {
        "reachable": False,
        "gateway": gateway,
        "packets_sent": count,
        "packets_received": 0,
        "packet_loss": 100.0,
        "avg_latency_ms": None,
    }

    try:
        result = context.run(cmd, check=False)
        result_info["reachable"] = result.returncode == 0

        if result.returncode == 0:
            # Parse stats
            stats_match = re.search(
                r"(\d+)\s+packets transmitted,\s+(\d+)\s+received", result.stdout
            )
            if stats_match:
                result_info["packets_sent"] = int(stats_match.group(1))
                result_info["packets_received"] = int(stats_match.group(2))
                if result_info["packets_sent"] > 0:
                    result_info["packet_loss"] = (
                        1 - result_info["packets_received"] / result_info["packets_sent"]
                    ) * 100

            # Parse latency
            rtt_match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", result.stdout)
            if rtt_match:
                result_info["avg_latency_ms"] = float(rtt_match.group(1))
    except Exception:
        pass

    return result_info


def check_interface_status(interface: str, context: Context) -> tuple[bool, str]:
    """Check if interface is up."""
    try:
        result = context.run(["ip", "link", "show", interface])
        if result.returncode != 0:
            return False, "not found"

        if "state UP" in result.stdout:
            return True, "UP"
        elif "state DOWN" in result.stdout:
            return False, "DOWN"
        else:
            state_match = re.search(r"state\s+(\S+)", result.stdout)
            if state_match:
                state = state_match.group(1)
                return state == "UP", state
    except Exception:
        pass

    return False, "UNKNOWN"


def analyze_routing_health(
    routes: list[dict],
    ping_results: dict[str, dict],
    interface_status: dict[str, tuple[bool, str]],
) -> tuple[list[dict], list[dict]]:
    """Analyze routing health and return issues/warnings."""
    issues = []
    warnings = []

    # Check for default routes
    default_routes = [r for r in routes if r["destination"] == "default"]
    if not default_routes:
        issues.append({
            "severity": "critical",
            "type": "no_default_route",
            "message": "No default route configured",
        })

    # Check gateway reachability
    for gateway, result in ping_results.items():
        if not result["reachable"]:
            issues.append({
                "severity": "critical",
                "type": "gateway_unreachable",
                "message": f"Default gateway {gateway} is unreachable",
                "gateway": gateway,
            })
        elif result["packet_loss"] > 0:
            warnings.append({
                "severity": "warning",
                "type": "gateway_packet_loss",
                "message": f"Gateway {gateway} has {result['packet_loss']:.1f}% packet loss",
                "gateway": gateway,
            })
        elif result["avg_latency_ms"] and result["avg_latency_ms"] > 100:
            warnings.append({
                "severity": "warning",
                "type": "gateway_high_latency",
                "message": f"Gateway {gateway} has high latency ({result['avg_latency_ms']:.1f}ms)",
                "gateway": gateway,
            })

    # Check interface status
    for interface, (is_up, status) in interface_status.items():
        if not is_up:
            issues.append({
                "severity": "critical",
                "type": "interface_down",
                "message": f"Interface {interface} used by route is {status}",
                "interface": interface,
            })

    # Check for multiple default routes with same metric
    ipv4_defaults = [r for r in default_routes if r["ip_version"] == "ipv4"]
    if len(ipv4_defaults) > 1:
        metrics = [r.get("metric") for r in ipv4_defaults]
        if len(set(metrics)) == 1:
            warnings.append({
                "severity": "warning",
                "type": "multiple_default_routes",
                "message": f"Multiple IPv4 default routes with same metric ({metrics[0]})",
                "count": len(ipv4_defaults),
            })

    return issues, warnings


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
        description="Monitor network routing health and gateway reachability"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--no-ping", action="store_true",
                        help="Skip gateway reachability checks")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show routes with issues")
    parser.add_argument("--ping-count", type=int, default=3,
                        help="Number of ping packets (default: 3)")
    parser.add_argument("--ping-timeout", type=int, default=2,
                        help="Ping timeout in seconds (default: 2)")
    opts = parser.parse_args(args)

    # Check for ip command
    if not context.check_tool("ip"):
        output.error("'ip' command not found. Install iproute2 package.")
        return 2

    # Get routes
    default_routes = get_default_routes(context)
    all_routes = get_all_routes(context) if opts.verbose else []

    # Check gateway reachability
    ping_results: dict[str, dict] = {}
    if not opts.no_ping:
        gateways = {r["gateway"] for r in default_routes if r["gateway"]}
        for gateway in gateways:
            ping_results[gateway] = ping_gateway(
                gateway, opts.ping_count, opts.ping_timeout, context
            )

    # Check interface status
    interface_status: dict[str, tuple[bool, str]] = {}
    interfaces = {r["interface"] for r in default_routes if r["interface"]}
    for interface in interfaces:
        interface_status[interface] = check_interface_status(interface, context)

    # Analyze
    issues, warnings = analyze_routing_health(default_routes, ping_results, interface_status)

    # Build result
    result_data = {
        "default_routes": default_routes,
        "gateway_status": ping_results,
        "interface_status": {k: {"up": v[0], "state": v[1]} for k, v in interface_status.items()},
        "issues": issues,
        "warnings": warnings,
        "healthy": len(issues) == 0,
    }
    if opts.verbose:
        result_data["all_routes"] = all_routes

    # Output
    if opts.format == "json":
        print(json.dumps(result_data, indent=2))
    else:
        print("Network Routing Health Monitor")
        print("=" * 60)
        print()

        if not opts.warn_only or not result_data["healthy"]:
            print("Default Routes:")
            print("-" * 40)
            if not default_routes:
                print("  [CRITICAL] No default routes configured!")
            else:
                for route in default_routes:
                    gw = route["gateway"] or "direct"
                    iface = route["interface"] or "unknown"
                    metric = route["metric"] if route["metric"] is not None else "default"
                    ipv = route["ip_version"].upper()
                    print(f"  [{ipv}] via {gw} dev {iface} metric {metric}")
            print()

        if ping_results and (not opts.warn_only or any(
            not r["reachable"] or r["packet_loss"] > 0 for r in ping_results.values()
        )):
            print("Gateway Reachability:")
            print("-" * 40)
            for gateway, res in ping_results.items():
                if opts.warn_only and res["reachable"] and res["packet_loss"] == 0:
                    continue
                status = "REACHABLE" if res["reachable"] else "UNREACHABLE"
                symbol = "+" if res["reachable"] else "X"
                latency = f" ({res['avg_latency_ms']:.1f}ms)" if res["avg_latency_ms"] else ""
                loss = f" [{res['packet_loss']:.0f}% loss]" if res["packet_loss"] > 0 else ""
                print(f"  [{symbol}] {gateway}: {status}{latency}{loss}")
            print()

        if interface_status and (not opts.warn_only or any(
            not v[0] for v in interface_status.values()
        )):
            print("Route Interfaces:")
            print("-" * 40)
            for iface, (is_up, state) in interface_status.items():
                if opts.warn_only and is_up:
                    continue
                symbol = "+" if is_up else "X"
                print(f"  [{symbol}] {iface}: {state}")
            print()

        if issues:
            print("Issues:")
            print("-" * 40)
            for issue in issues:
                print(f"  [CRITICAL] {issue['message']}")
            print()

        if warnings:
            print("Warnings:")
            print("-" * 40)
            for warning in warnings:
                print(f"  [WARNING] {warning['message']}")
            print()

        if result_data["healthy"] and not warnings:
            print("Status: All routing healthy")
        elif result_data["healthy"] and warnings:
            print(f"Status: Routing functional with {len(warnings)} warning(s)")
        else:
            print(f"Status: {len(issues)} issue(s) detected")

    output.emit(result_data)

    if issues:
        output.set_summary(f"{len(issues)} routing issues")
        return 1

    output.set_summary("Routing healthy")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
