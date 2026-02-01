#!/usr/bin/env python3
"""
Monitor Linux NAPI (New API) polling health for network performance issues.

NAPI is the Linux kernel's mechanism for efficient network packet processing.
Instead of generating an interrupt for each packet, NAPI allows the kernel to
poll network devices in batches, reducing CPU overhead at high packet rates.

This script monitors NAPI-related statistics from /proc and /sys:
- NAPI polling budget utilization (gro_normal_batch)
- Per-interface NAPI statistics
- Busy polling configuration
- Network device queue depths
- NAPI-related softirq statistics

Common causes of NAPI performance issues:
- Budget exhaustion (packets processed per poll too low)
- Busy polling misconfigured for latency-sensitive workloads
- GRO/LRO settings suboptimal
- Network driver NAPI weight settings

Remediation:
- Increase NAPI weight: echo 64 > /sys/class/net/<iface>/napi_defer_hard_irqs
- Enable busy polling: sysctl -w net.core.busy_poll=50
- Tune GRO batch: sysctl -w net.core.gro_normal_batch=8
- Check driver-specific NAPI settings

Exit codes:
    0 - NAPI configuration healthy
    1 - Potential performance issues detected
    2 - Cannot read NAPI statistics or usage error
"""

import argparse
import sys
import json
import os
import glob as globlib


def read_sysctl(path):
    """
    Read a sysctl value from /proc/sys path.

    Args:
        path: Path under /proc/sys

    Returns:
        Value as int or string, or None if not readable
    """
    try:
        with open(path, 'r') as f:
            value = f.read().strip()
            try:
                return int(value)
            except ValueError:
                return value
    except (FileNotFoundError, PermissionError, IOError):
        return None


def get_network_interfaces():
    """
    Get list of network interfaces with their basic info.

    Returns:
        list: List of interface dictionaries
    """
    interfaces = []

    try:
        net_path = '/sys/class/net'
        if not os.path.isdir(net_path):
            return interfaces

        for iface in os.listdir(net_path):
            iface_path = os.path.join(net_path, iface)
            if not os.path.isdir(iface_path):
                continue

            # Skip loopback
            if iface == 'lo':
                continue

            info = {
                'name': iface,
                'path': iface_path,
            }

            # Read operstate
            operstate = read_sysctl(os.path.join(iface_path, 'operstate'))
            info['operstate'] = operstate if operstate else 'unknown'

            # Read carrier (link status)
            carrier = read_sysctl(os.path.join(iface_path, 'carrier'))
            info['carrier'] = carrier == 1 if carrier is not None else None

            # Read speed if available
            speed = read_sysctl(os.path.join(iface_path, 'speed'))
            if speed is not None and speed > 0:
                info['speed_mbps'] = speed

            # Check for NAPI defer hard IRQs setting
            napi_defer = read_sysctl(os.path.join(iface_path, 'napi_defer_hard_irqs'))
            if napi_defer is not None:
                info['napi_defer_hard_irqs'] = napi_defer

            # Check for GRO flush timeout
            gro_timeout = read_sysctl(os.path.join(iface_path, 'gro_flush_timeout'))
            if gro_timeout is not None:
                info['gro_flush_timeout'] = gro_timeout

            interfaces.append(info)

    except (OSError, IOError):
        pass

    return interfaces


def get_napi_settings():
    """
    Read global NAPI-related kernel settings.

    Returns:
        dict: Dictionary of NAPI settings
    """
    settings = {}

    sysctl_paths = {
        'busy_poll': '/proc/sys/net/core/busy_poll',
        'busy_read': '/proc/sys/net/core/busy_read',
        'gro_normal_batch': '/proc/sys/net/core/gro_normal_batch',
        'netdev_budget': '/proc/sys/net/core/netdev_budget',
        'netdev_budget_usecs': '/proc/sys/net/core/netdev_budget_usecs',
        'dev_weight': '/proc/sys/net/core/dev_weight',
        'dev_weight_rx_bias': '/proc/sys/net/core/dev_weight_rx_bias',
        'dev_weight_tx_bias': '/proc/sys/net/core/dev_weight_tx_bias',
    }

    for name, path in sysctl_paths.items():
        value = read_sysctl(path)
        if value is not None:
            settings[name] = value

    return settings


def get_interface_queues(iface_path):
    """
    Get RX/TX queue information for an interface.

    Args:
        iface_path: Path to interface in /sys/class/net

    Returns:
        dict: Queue information
    """
    queues = {
        'rx_queues': 0,
        'tx_queues': 0,
        'rx_queue_details': [],
        'tx_queue_details': [],
    }

    # Count RX queues
    rx_path = os.path.join(iface_path, 'queues')
    if os.path.isdir(rx_path):
        try:
            entries = os.listdir(rx_path)
            queues['rx_queues'] = len([e for e in entries if e.startswith('rx-')])
            queues['tx_queues'] = len([e for e in entries if e.startswith('tx-')])

            # Get RPS CPU settings for RX queues
            for entry in sorted(entries):
                if entry.startswith('rx-'):
                    rps_cpus = read_sysctl(os.path.join(rx_path, entry, 'rps_cpus'))
                    rps_flow = read_sysctl(os.path.join(rx_path, entry, 'rps_flow_cnt'))
                    queues['rx_queue_details'].append({
                        'queue': entry,
                        'rps_cpus': rps_cpus,
                        'rps_flow_cnt': rps_flow,
                    })
        except (OSError, IOError):
            pass

    return queues


def get_softirq_stats():
    """
    Read softirq statistics related to networking.

    Returns:
        dict: Softirq statistics
    """
    stats = {
        'net_rx': [],
        'net_tx': [],
        'total_net_rx': 0,
        'total_net_tx': 0,
    }

    try:
        with open('/proc/softirqs', 'r') as f:
            lines = f.readlines()

        # Parse header to get CPU columns
        if not lines:
            return stats

        header = lines[0].split()
        num_cpus = len(header)

        for line in lines[1:]:
            parts = line.split()
            if not parts:
                continue

            irq_name = parts[0].rstrip(':')
            values = [int(v) for v in parts[1:num_cpus + 1]]

            if irq_name == 'NET_RX':
                stats['net_rx'] = values
                stats['total_net_rx'] = sum(values)
            elif irq_name == 'NET_TX':
                stats['net_tx'] = values
                stats['total_net_tx'] = sum(values)

    except (FileNotFoundError, PermissionError, IOError, ValueError):
        pass

    return stats


def analyze_napi_health(settings, interfaces, softirq_stats):
    """
    Analyze NAPI configuration and generate issues.

    Args:
        settings: Global NAPI settings
        interfaces: List of interface info
        softirq_stats: Softirq statistics

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Check if busy polling is disabled for latency-sensitive environments
    busy_poll = settings.get('busy_poll', 0)
    busy_read = settings.get('busy_read', 0)

    # Check netdev_budget (default 300, may need tuning for high throughput)
    netdev_budget = settings.get('netdev_budget')
    if netdev_budget is not None and netdev_budget < 300:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_netdev_budget',
            'value': netdev_budget,
            'message': f"netdev_budget is low ({netdev_budget}). "
                      f"Consider increasing for high packet rates: "
                      f"sysctl -w net.core.netdev_budget=600"
        })

    # Check dev_weight (NAPI weight, default 64)
    dev_weight = settings.get('dev_weight')
    if dev_weight is not None and dev_weight < 64:
        issues.append({
            'severity': 'INFO',
            'type': 'low_dev_weight',
            'value': dev_weight,
            'message': f"dev_weight is {dev_weight} (default 64). "
                      f"Lower values may reduce throughput but improve latency."
        })

    # Check GRO batch size
    gro_batch = settings.get('gro_normal_batch')
    if gro_batch is not None and gro_batch < 8:
        issues.append({
            'severity': 'INFO',
            'type': 'low_gro_batch',
            'value': gro_batch,
            'message': f"gro_normal_batch is {gro_batch}. "
                      f"Consider increasing for better GRO coalescing: "
                      f"sysctl -w net.core.gro_normal_batch=8"
        })

    # Check per-interface NAPI settings
    for iface in interfaces:
        if iface.get('operstate') != 'up':
            continue

        # Check NAPI defer hard IRQs
        napi_defer = iface.get('napi_defer_hard_irqs')
        if napi_defer is not None and napi_defer == 0:
            # NAPI defer disabled, which may cause more interrupts
            speed = iface.get('speed_mbps', 0)
            if speed >= 10000:  # 10Gbps or higher
                issues.append({
                    'severity': 'INFO',
                    'type': 'napi_defer_disabled',
                    'interface': iface['name'],
                    'message': f"Interface {iface['name']} ({speed}Mbps) has "
                              f"napi_defer_hard_irqs=0. For high-speed interfaces, "
                              f"consider enabling: echo 2 > /sys/class/net/{iface['name']}/napi_defer_hard_irqs"
                })

    # Check for NET_RX softirq imbalance across CPUs
    net_rx = softirq_stats.get('net_rx', [])
    if len(net_rx) >= 2:
        max_rx = max(net_rx)
        min_rx = min(net_rx)
        if min_rx > 0:
            ratio = max_rx / min_rx
            if ratio > 10:
                max_cpu = net_rx.index(max_rx)
                min_cpu = net_rx.index(min_rx)
                issues.append({
                    'severity': 'WARNING',
                    'type': 'softirq_imbalance',
                    'max_cpu': max_cpu,
                    'min_cpu': min_cpu,
                    'ratio': ratio,
                    'message': f"NET_RX softirq imbalance detected: CPU{max_cpu} "
                              f"processed {ratio:.1f}x more than CPU{min_cpu}. "
                              f"Consider configuring RPS or checking IRQ affinity."
                })
        elif max_rx > 0:
            # All on one CPU
            max_cpu = net_rx.index(max_rx)
            issues.append({
                'severity': 'WARNING',
                'type': 'softirq_single_cpu',
                'cpu': max_cpu,
                'message': f"All NET_RX softirqs handled by CPU{max_cpu}. "
                          f"Consider enabling RPS for better distribution."
            })

    return issues


def format_plain(settings, interfaces, softirq_stats, issues, verbose=False, warn_only=False):
    """Format output as plain text."""
    lines = []

    if warn_only and not issues:
        return "No NAPI issues detected"

    if not warn_only:
        lines.append("NAPI Health Monitor")
        lines.append("=" * 60)
        lines.append("")

        # Global settings
        lines.append("Global NAPI Settings:")
        lines.append(f"  netdev_budget:      {settings.get('netdev_budget', 'N/A'):>10}")
        lines.append(f"  dev_weight:         {settings.get('dev_weight', 'N/A'):>10}")
        lines.append(f"  gro_normal_batch:   {settings.get('gro_normal_batch', 'N/A'):>10}")
        lines.append(f"  busy_poll:          {settings.get('busy_poll', 'N/A'):>10} us")
        lines.append(f"  busy_read:          {settings.get('busy_read', 'N/A'):>10} us")
        if 'netdev_budget_usecs' in settings:
            lines.append(f"  netdev_budget_usecs:{settings['netdev_budget_usecs']:>10} us")
        lines.append("")

        # Softirq stats
        lines.append("NET Softirq Statistics:")
        lines.append(f"  Total NET_RX:       {softirq_stats.get('total_net_rx', 0):>15,}")
        lines.append(f"  Total NET_TX:       {softirq_stats.get('total_net_tx', 0):>15,}")
        lines.append("")

        # Interface summary
        up_interfaces = [i for i in interfaces if i.get('operstate') == 'up']
        if up_interfaces:
            lines.append("Active Interfaces:")
            for iface in up_interfaces:
                speed = iface.get('speed_mbps', 'N/A')
                napi_defer = iface.get('napi_defer_hard_irqs', 'N/A')
                lines.append(f"  {iface['name']:<15} speed={speed}Mbps  napi_defer={napi_defer}")
            lines.append("")

        # Per-CPU softirq distribution (verbose)
        if verbose and softirq_stats.get('net_rx'):
            lines.append("Per-CPU NET_RX Distribution:")
            for cpu, count in enumerate(softirq_stats['net_rx']):
                lines.append(f"  CPU{cpu:<4} {count:>15,}")
            lines.append("")

    # Issues
    if issues:
        lines.append("Issues Detected:")
        lines.append("-" * 60)
        for issue in sorted(issues, key=lambda x: (
            x['severity'] != 'WARNING',
            x['severity'] != 'INFO'
        )):
            marker = " ! " if issue['severity'] == 'WARNING' else "   "
            lines.append(f"{marker}[{issue['severity']}] {issue['message']}")
        lines.append("")
    elif not warn_only:
        lines.append("Status: NAPI configuration healthy")

    return '\n'.join(lines)


def format_json(settings, interfaces, softirq_stats, issues):
    """Format output as JSON."""
    output = {
        'settings': settings,
        'interfaces': interfaces,
        'softirq_stats': softirq_stats,
        'issues': issues,
        'healthy': not any(i['severity'] == 'WARNING' for i in issues),
    }
    return json.dumps(output, indent=2)


def format_table(settings, interfaces, softirq_stats, issues):
    """Format output as a table."""
    lines = []

    lines.append(f"{'Setting':<25} {'Value':>15}")
    lines.append("=" * 42)

    for key in ['netdev_budget', 'dev_weight', 'gro_normal_batch', 'busy_poll', 'busy_read']:
        value = settings.get(key, 'N/A')
        lines.append(f"{key:<25} {value:>15}")

    lines.append("")
    lines.append(f"{'Interface':<15} {'State':<10} {'Speed':>10} {'NAPI Defer':>10}")
    lines.append("-" * 47)

    for iface in interfaces:
        state = iface.get('operstate', 'unknown')
        speed = iface.get('speed_mbps', 'N/A')
        napi_defer = iface.get('napi_defer_hard_irqs', 'N/A')
        lines.append(f"{iface['name']:<15} {state:<10} {speed:>10} {napi_defer:>10}")

    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            lines.append(f"  [{issue['severity']}] {issue['message']}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Linux NAPI polling health for network performance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic NAPI health check
  %(prog)s -v                       # Show per-CPU softirq distribution
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --warn-only              # Only show if issues detected

NAPI tuning tips:
  - Increase netdev_budget for high packet rates
  - Enable busy polling for latency-sensitive workloads
  - Configure RPS for multi-CPU packet distribution
  - Adjust napi_defer_hard_irqs for interrupt coalescing

Exit codes:
  0 - NAPI configuration healthy
  1 - Potential performance issues detected
  2 - Cannot read NAPI statistics
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed per-CPU statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if issues are detected'
    )

    args = parser.parse_args()

    # Verify we're on Linux
    if not os.path.isdir('/proc/sys/net'):
        print("Error: Cannot read /proc/sys/net", file=sys.stderr)
        print("This script requires a Linux system with procfs mounted", file=sys.stderr)
        sys.exit(2)

    # Gather data
    settings = get_napi_settings()
    interfaces = get_network_interfaces()
    softirq_stats = get_softirq_stats()

    # Verify we got some data
    if not settings:
        print("Error: Cannot read NAPI kernel settings", file=sys.stderr)
        sys.exit(2)

    # Analyze health
    issues = analyze_napi_health(settings, interfaces, softirq_stats)

    # Handle warn-only mode with no issues
    if args.warn_only and not issues:
        if args.format == 'json':
            print(json.dumps({'healthy': True, 'issues': []}))
        sys.exit(0)

    # Format output
    if args.format == 'json':
        output = format_json(settings, interfaces, softirq_stats, issues)
    elif args.format == 'table':
        output = format_table(settings, interfaces, softirq_stats, issues)
    else:
        output = format_plain(settings, interfaces, softirq_stats, issues,
                             verbose=args.verbose, warn_only=args.warn_only)

    print(output)

    # Exit code based on issues
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
