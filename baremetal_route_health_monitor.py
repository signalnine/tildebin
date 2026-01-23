#!/usr/bin/env python3
"""
Monitor network routing health including default gateway reachability.

Checks routing table consistency, default gateway availability, and
detects routing issues that could cause connectivity problems in
large-scale baremetal environments.

Exit codes:
    0 - All routes healthy, gateway reachable
    1 - Routing issues detected (unreachable gateway, missing routes)
    2 - Usage error or missing dependency
"""

import argparse
import subprocess
import sys
import json
import re


def run_command(cmd):
    """Execute a command and return output"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_ip_command():
    """Verify ip command is available"""
    returncode, _, _ = run_command(['ip', '-V'])
    return returncode == 0


def get_default_routes():
    """Get all default routes from the routing table"""
    routes = []

    # Get IPv4 default routes
    returncode, stdout, _ = run_command(['ip', '-4', 'route', 'show', 'default'])
    if returncode == 0 and stdout.strip():
        for line in stdout.strip().split('\n'):
            route = parse_route_line(line, 'ipv4')
            if route:
                routes.append(route)

    # Get IPv6 default routes
    returncode, stdout, _ = run_command(['ip', '-6', 'route', 'show', 'default'])
    if returncode == 0 and stdout.strip():
        for line in stdout.strip().split('\n'):
            route = parse_route_line(line, 'ipv6')
            if route:
                routes.append(route)

    return routes


def parse_route_line(line, ip_version):
    """Parse a route line from ip route output"""
    if not line.strip():
        return None

    route = {
        'destination': 'default',
        'gateway': None,
        'interface': None,
        'metric': None,
        'ip_version': ip_version,
        'raw': line.strip()
    }

    # Parse gateway (via X.X.X.X)
    via_match = re.search(r'via\s+(\S+)', line)
    if via_match:
        route['gateway'] = via_match.group(1)

    # Parse interface (dev ethX)
    dev_match = re.search(r'dev\s+(\S+)', line)
    if dev_match:
        route['interface'] = dev_match.group(1)

    # Parse metric
    metric_match = re.search(r'metric\s+(\d+)', line)
    if metric_match:
        route['metric'] = int(metric_match.group(1))

    return route


def get_all_routes():
    """Get all routes from the routing table"""
    routes = []

    # Get IPv4 routes
    returncode, stdout, _ = run_command(['ip', '-4', 'route', 'show'])
    if returncode == 0:
        for line in stdout.strip().split('\n'):
            if line.strip():
                route = parse_full_route_line(line, 'ipv4')
                if route:
                    routes.append(route)

    return routes


def parse_full_route_line(line, ip_version):
    """Parse any route line from ip route output"""
    if not line.strip():
        return None

    parts = line.split()
    if not parts:
        return None

    route = {
        'destination': parts[0],
        'gateway': None,
        'interface': None,
        'metric': None,
        'scope': None,
        'ip_version': ip_version,
        'raw': line.strip()
    }

    # Parse gateway
    via_match = re.search(r'via\s+(\S+)', line)
    if via_match:
        route['gateway'] = via_match.group(1)

    # Parse interface
    dev_match = re.search(r'dev\s+(\S+)', line)
    if dev_match:
        route['interface'] = dev_match.group(1)

    # Parse metric
    metric_match = re.search(r'metric\s+(\d+)', line)
    if metric_match:
        route['metric'] = int(metric_match.group(1))

    # Parse scope
    scope_match = re.search(r'scope\s+(\S+)', line)
    if scope_match:
        route['scope'] = scope_match.group(1)

    return route


def ping_gateway(gateway, count=3, timeout=2):
    """Ping a gateway to check reachability"""
    # Determine if IPv6
    is_ipv6 = ':' in gateway

    cmd = [
        'ping6' if is_ipv6 else 'ping',
        '-c', str(count),
        '-W', str(timeout),
        gateway
    ]

    returncode, stdout, stderr = run_command(cmd)

    result = {
        'reachable': returncode == 0,
        'gateway': gateway,
        'packets_sent': count,
        'packets_received': 0,
        'packet_loss': 100.0,
        'avg_latency_ms': None
    }

    if returncode == 0:
        # Parse ping output for statistics
        # Look for "X packets transmitted, Y received"
        stats_match = re.search(r'(\d+)\s+packets transmitted,\s+(\d+)\s+received', stdout)
        if stats_match:
            result['packets_sent'] = int(stats_match.group(1))
            result['packets_received'] = int(stats_match.group(2))
            if result['packets_sent'] > 0:
                result['packet_loss'] = (1 - result['packets_received'] / result['packets_sent']) * 100

        # Parse average latency
        # Look for "rtt min/avg/max/mdev = X/Y/Z/W ms"
        rtt_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', stdout)
        if rtt_match:
            result['avg_latency_ms'] = float(rtt_match.group(1))

    return result


def check_interface_status(interface):
    """Check if an interface is up"""
    returncode, stdout, _ = run_command(['ip', 'link', 'show', interface])
    if returncode != 0:
        return False, "not found"

    if 'state UP' in stdout:
        return True, "UP"
    elif 'state DOWN' in stdout:
        return False, "DOWN"
    else:
        # Try to extract actual state
        state_match = re.search(r'state\s+(\S+)', stdout)
        if state_match:
            state = state_match.group(1)
            return state == 'UP', state

    return False, "UNKNOWN"


def analyze_routing_health(routes, ping_results, interface_status, verbose=False):
    """Analyze overall routing health and return issues"""
    issues = []
    warnings = []

    # Check if we have any default routes
    default_routes = [r for r in routes if r['destination'] == 'default']
    if not default_routes:
        issues.append({
            'severity': 'critical',
            'type': 'no_default_route',
            'message': 'No default route configured'
        })

    # Check gateway reachability
    for gateway, result in ping_results.items():
        if not result['reachable']:
            issues.append({
                'severity': 'critical',
                'type': 'gateway_unreachable',
                'message': f"Default gateway {gateway} is unreachable",
                'gateway': gateway
            })
        elif result['packet_loss'] > 0:
            warnings.append({
                'severity': 'warning',
                'type': 'gateway_packet_loss',
                'message': f"Gateway {gateway} has {result['packet_loss']:.1f}% packet loss",
                'gateway': gateway,
                'packet_loss': result['packet_loss']
            })
        elif result['avg_latency_ms'] and result['avg_latency_ms'] > 100:
            warnings.append({
                'severity': 'warning',
                'type': 'gateway_high_latency',
                'message': f"Gateway {gateway} has high latency ({result['avg_latency_ms']:.1f}ms)",
                'gateway': gateway,
                'latency_ms': result['avg_latency_ms']
            })

    # Check interface status for routes
    for interface, (is_up, status) in interface_status.items():
        if not is_up:
            issues.append({
                'severity': 'critical',
                'type': 'interface_down',
                'message': f"Interface {interface} used by route is {status}",
                'interface': interface
            })

    # Check for multiple default routes (potential issue)
    ipv4_defaults = [r for r in default_routes if r['ip_version'] == 'ipv4']
    if len(ipv4_defaults) > 1:
        metrics = [r.get('metric') for r in ipv4_defaults]
        if len(set(metrics)) == 1:
            warnings.append({
                'severity': 'warning',
                'type': 'multiple_default_routes',
                'message': f"Multiple IPv4 default routes with same metric ({metrics[0]})",
                'count': len(ipv4_defaults)
            })

    return issues, warnings


def main():
    parser = argparse.ArgumentParser(
        description="Monitor network routing health and gateway reachability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Check all default routes and gateways
  %(prog)s --no-ping          Check routes without pinging gateways
  %(prog)s --format json      Output results as JSON
  %(prog)s -v                 Show verbose route information
  %(prog)s --warn-only        Only show routes with issues
"""
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed route and gateway information"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Skip gateway reachability checks (no ICMP ping)"
    )

    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Only show routes or gateways with issues"
    )

    parser.add_argument(
        "--ping-count",
        type=int,
        default=3,
        help="Number of ping packets to send (default: 3)"
    )

    parser.add_argument(
        "--ping-timeout",
        type=int,
        default=2,
        help="Ping timeout in seconds (default: 2)"
    )

    args = parser.parse_args()

    # Check for ip command
    if not check_ip_command():
        print("Error: 'ip' command not found", file=sys.stderr)
        print("Install iproute2: sudo apt-get install iproute2", file=sys.stderr)
        sys.exit(2)

    # Get routing information
    default_routes = get_default_routes()
    all_routes = get_all_routes() if args.verbose else []

    # Check gateway reachability
    ping_results = {}
    if not args.no_ping:
        gateways = set()
        for route in default_routes:
            if route['gateway']:
                gateways.add(route['gateway'])

        for gateway in gateways:
            ping_results[gateway] = ping_gateway(
                gateway,
                count=args.ping_count,
                timeout=args.ping_timeout
            )

    # Check interface status
    interface_status = {}
    interfaces = set()
    for route in default_routes:
        if route['interface']:
            interfaces.add(route['interface'])

    for interface in interfaces:
        interface_status[interface] = check_interface_status(interface)

    # Analyze health
    issues, warnings = analyze_routing_health(
        default_routes,
        ping_results,
        interface_status,
        args.verbose
    )

    # Prepare results
    results = {
        'default_routes': default_routes,
        'gateway_status': ping_results,
        'interface_status': {k: {'up': v[0], 'state': v[1]} for k, v in interface_status.items()},
        'issues': issues,
        'warnings': warnings,
        'healthy': len(issues) == 0
    }

    if args.verbose:
        results['all_routes'] = all_routes

    # Output results
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        print("Network Routing Health Monitor")
        print("=" * 60)
        print()

        # Show default routes
        if not args.warn_only or not results['healthy']:
            print("Default Routes:")
            print("-" * 40)
            if not default_routes:
                print("  [CRITICAL] No default routes configured!")
            else:
                for route in default_routes:
                    gw = route['gateway'] or 'direct'
                    iface = route['interface'] or 'unknown'
                    metric = route['metric'] if route['metric'] is not None else 'default'
                    ipv = route['ip_version'].upper()
                    print(f"  [{ipv}] via {gw} dev {iface} metric {metric}")
            print()

        # Show gateway status
        if ping_results and (not args.warn_only or any(not r['reachable'] or r['packet_loss'] > 0 for r in ping_results.values())):
            print("Gateway Reachability:")
            print("-" * 40)
            for gateway, result in ping_results.items():
                if args.warn_only and result['reachable'] and result['packet_loss'] == 0:
                    continue

                status = "REACHABLE" if result['reachable'] else "UNREACHABLE"
                symbol = "✓" if result['reachable'] else "✗"
                latency = f" ({result['avg_latency_ms']:.1f}ms)" if result['avg_latency_ms'] else ""
                loss = f" [{result['packet_loss']:.0f}% loss]" if result['packet_loss'] > 0 else ""
                print(f"  {symbol} {gateway}: {status}{latency}{loss}")
            print()

        # Show interface status
        if interface_status and (not args.warn_only or any(not v[0] for v in interface_status.values())):
            print("Route Interfaces:")
            print("-" * 40)
            for interface, (is_up, state) in interface_status.items():
                if args.warn_only and is_up:
                    continue
                symbol = "✓" if is_up else "✗"
                print(f"  {symbol} {interface}: {state}")
            print()

        # Show issues and warnings
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

        # Summary
        if results['healthy'] and not warnings:
            print("Status: All routing healthy ✓")
        elif results['healthy'] and warnings:
            print(f"Status: Routing functional with {len(warnings)} warning(s)")
        else:
            print(f"Status: {len(issues)} issue(s) detected ✗")

    # Exit code
    if issues:
        sys.exit(1)
    elif warnings:
        sys.exit(0)  # Warnings don't cause failure
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
