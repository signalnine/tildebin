#!/usr/bin/env python3
"""
Detect network interface link flapping on baremetal systems.

Link flapping occurs when a network interface repeatedly transitions between
up and down states. This can be caused by:
- Failing cables or transceivers
- Bad switch ports
- Auto-negotiation issues
- Power supply problems
- Driver bugs

This script monitors the carrier state of network interfaces and detects
flapping by counting state transitions over a monitoring window.

Exit codes:
    0 - No flapping detected
    1 - Link flapping detected on one or more interfaces
    2 - Missing /sys filesystem or usage error
"""

import argparse
import sys
import json
import os
import time


def get_interface_list():
    """Get list of network interfaces from /sys/class/net."""
    try:
        interfaces = []
        net_path = '/sys/class/net'
        if not os.path.exists(net_path):
            return None

        for iface in os.listdir(net_path):
            # Skip loopback
            if iface == 'lo':
                continue
            # Skip virtual interfaces
            if iface.startswith('veth') or iface.startswith('docker'):
                continue
            # Skip bonding_masters (not a real interface)
            if iface == 'bonding_masters':
                continue
            # Verify it's a real interface (has carrier file)
            carrier_path = os.path.join(net_path, iface, 'carrier')
            if not os.path.exists(carrier_path):
                continue
            interfaces.append(iface)

        return sorted(interfaces)
    except (PermissionError, OSError):
        return None


def read_carrier_state(iface):
    """Read carrier state (link up/down) from /sys/class/net/<iface>/carrier.

    Returns:
        1 = link up (carrier detected)
        0 = link down (no carrier)
        None = unable to read (interface may be admin down)
    """
    path = f'/sys/class/net/{iface}/carrier'
    try:
        with open(path, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return None
    except OSError:
        # Interface may be admin down, which gives "Invalid argument"
        return 0


def read_operstate(iface):
    """Read operational state from /sys/class/net/<iface>/operstate."""
    path = f'/sys/class/net/{iface}/operstate'
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return 'unknown'


def read_carrier_changes(iface):
    """Read carrier_changes counter from /sys/class/net/<iface>/carrier_changes.

    This kernel counter tracks total link state transitions since boot.
    Available since Linux 3.18.
    """
    path = f'/sys/class/net/{iface}/carrier_changes'
    try:
        with open(path, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return None


def read_carrier_up_count(iface):
    """Read carrier_up_count from /sys/class/net/<iface>/carrier_up_count.

    Available since Linux 5.0.
    """
    path = f'/sys/class/net/{iface}/carrier_up_count'
    try:
        with open(path, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return None


def read_carrier_down_count(iface):
    """Read carrier_down_count from /sys/class/net/<iface>/carrier_down_count.

    Available since Linux 5.0.
    """
    path = f'/sys/class/net/{iface}/carrier_down_count'
    try:
        with open(path, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return None


def get_interface_speed(iface):
    """Get interface speed in Mbps from /sys/class/net/<iface>/speed."""
    path = f'/sys/class/net/{iface}/speed'
    try:
        with open(path, 'r') as f:
            speed = int(f.read().strip())
            if speed > 0:
                return speed
            return None
    except (FileNotFoundError, PermissionError, ValueError, OSError):
        return None


def get_interface_info(iface):
    """Get comprehensive interface information."""
    return {
        'interface': iface,
        'carrier': read_carrier_state(iface),
        'operstate': read_operstate(iface),
        'carrier_changes': read_carrier_changes(iface),
        'carrier_up_count': read_carrier_up_count(iface),
        'carrier_down_count': read_carrier_down_count(iface),
        'speed_mbps': get_interface_speed(iface),
    }


def monitor_interfaces(interfaces, duration, poll_interval):
    """Monitor interfaces for link flapping over a duration.

    Returns dict of interface -> list of state transitions
    """
    transitions = {iface: [] for iface in interfaces}
    last_state = {}

    # Get initial state
    for iface in interfaces:
        last_state[iface] = read_carrier_state(iface)

    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        time.sleep(poll_interval)
        current_time = time.time() - start_time

        for iface in interfaces:
            current_state = read_carrier_state(iface)
            if current_state != last_state[iface]:
                transitions[iface].append({
                    'time': round(current_time, 2),
                    'from': 'up' if last_state[iface] == 1 else 'down',
                    'to': 'up' if current_state == 1 else 'down',
                })
                last_state[iface] = current_state

    return transitions


def analyze_flapping(interfaces, duration, poll_interval, flap_threshold):
    """Analyze interfaces for link flapping.

    Uses kernel carrier_changes counter if available, otherwise monitors
    the carrier state over the specified duration.
    """
    results = []
    issues = []

    # First, get static info and kernel counters
    for iface in interfaces:
        info = get_interface_info(iface)

        # Check if kernel carrier_changes counter is available
        if info['carrier_changes'] is not None:
            # Use kernel counter - more accurate, less overhead
            start_changes = info['carrier_changes']
            time.sleep(duration)
            end_changes = read_carrier_changes(iface)

            if end_changes is not None:
                changes_during_window = end_changes - start_changes
                flaps = changes_during_window // 2  # Each flap = down + up = 2 changes

                result = {
                    'interface': iface,
                    'operstate': info['operstate'],
                    'carrier': 'up' if info['carrier'] == 1 else 'down',
                    'speed_mbps': info['speed_mbps'],
                    'monitoring_method': 'kernel_counter',
                    'monitoring_duration_sec': duration,
                    'carrier_changes_start': start_changes,
                    'carrier_changes_end': end_changes,
                    'carrier_changes_during_window': changes_during_window,
                    'estimated_flaps': flaps,
                    'total_carrier_changes': end_changes,
                    'carrier_up_count': read_carrier_up_count(iface),
                    'carrier_down_count': read_carrier_down_count(iface),
                    'flapping': changes_during_window >= flap_threshold,
                    'transitions': [],
                }

                if result['flapping']:
                    issues.append({
                        'interface': iface,
                        'severity': 'warning' if changes_during_window < flap_threshold * 2 else 'critical',
                        'message': f"{iface}: {changes_during_window} carrier changes in {duration}s "
                                   f"(threshold: {flap_threshold})",
                        'carrier_changes': changes_during_window,
                    })

                results.append(result)
                continue

        # Fall back to polling if kernel counter not available
        result = {
            'interface': iface,
            'operstate': info['operstate'],
            'carrier': 'up' if info['carrier'] == 1 else 'down',
            'speed_mbps': info['speed_mbps'],
            'monitoring_method': 'polling',
            'monitoring_duration_sec': duration,
            'poll_interval_sec': poll_interval,
            'carrier_changes_during_window': 0,
            'estimated_flaps': 0,
            'total_carrier_changes': info['carrier_changes'],
            'carrier_up_count': info['carrier_up_count'],
            'carrier_down_count': info['carrier_down_count'],
            'flapping': False,
            'transitions': [],
        }
        results.append(result)

    # If we need to do polling-based monitoring
    polling_interfaces = [r['interface'] for r in results if r['monitoring_method'] == 'polling']
    if polling_interfaces:
        transitions = monitor_interfaces(polling_interfaces, duration, poll_interval)

        for result in results:
            if result['interface'] in polling_interfaces:
                iface = result['interface']
                trans = transitions.get(iface, [])
                result['transitions'] = trans
                result['carrier_changes_during_window'] = len(trans)
                result['estimated_flaps'] = len(trans) // 2
                result['flapping'] = len(trans) >= flap_threshold

                if result['flapping']:
                    issues.append({
                        'interface': iface,
                        'severity': 'warning' if len(trans) < flap_threshold * 2 else 'critical',
                        'message': f"{iface}: {len(trans)} carrier changes in {duration}s "
                                   f"(threshold: {flap_threshold})",
                        'carrier_changes': len(trans),
                    })

    return results, issues


def output_plain(results, issues, duration, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    print("Link Flapping Detection")
    print("=" * 70)
    print(f"Monitoring duration: {duration}s")
    print()

    for result in results:
        if warn_only and not result['flapping']:
            continue

        status = "FLAPPING" if result['flapping'] else "STABLE"
        carrier = result['carrier'].upper()
        speed = f"{result['speed_mbps']}Mbps" if result['speed_mbps'] else "N/A"

        print(f"[{status}] {result['interface']} ({carrier}) - {speed}")

        changes = result['carrier_changes_during_window']
        total = result.get('total_carrier_changes', 'N/A')
        method = result['monitoring_method']

        print(f"  Changes during window: {changes} (method: {method})")
        print(f"  Total carrier changes since boot: {total}")

        if result['carrier_up_count'] is not None:
            print(f"  Carrier up/down count: {result['carrier_up_count']}/{result['carrier_down_count']}")

        if verbose and result['transitions']:
            print("  Transitions detected:")
            for trans in result['transitions'][:10]:  # Limit to first 10
                print(f"    {trans['time']:6.2f}s: {trans['from']} -> {trans['to']}")
            if len(result['transitions']) > 10:
                print(f"    ... and {len(result['transitions']) - 10} more")

        print()

    # Summary
    if issues:
        print(f"Summary: {len(issues)} interface(s) with link flapping detected")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")
    elif not warn_only:
        print("Summary: No link flapping detected")


def output_json(results, issues, duration):
    """Output results in JSON format."""
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'monitoring_duration_sec': duration,
        'interfaces': results,
        'issues': issues,
        'summary': {
            'interfaces_checked': len(results),
            'interfaces_flapping': len([r for r in results if r['flapping']]),
            'total_issues': len(issues),
        },
        'has_flapping': any(r['flapping'] for r in results),
    }
    print(json.dumps(output, indent=2))


def output_table(results, issues, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    # Header
    print(f"{'Interface':<15} {'State':<8} {'Status':<10} {'Speed':<12} "
          f"{'Changes':>10} {'Total':>10} {'Method':<10}")
    print("-" * 85)

    for result in results:
        if warn_only and not result['flapping']:
            continue

        status = "FLAPPING" if result['flapping'] else "STABLE"
        speed = f"{result['speed_mbps']}Mbps" if result['speed_mbps'] else "N/A"
        total = result.get('total_carrier_changes', 'N/A')

        print(f"{result['interface']:<15} {result['carrier'].upper():<8} {status:<10} "
              f"{speed:<12} {result['carrier_changes_during_window']:>10} "
              f"{str(total):>10} {result['monitoring_method']:<10}")

    if issues:
        print()
        print(f"Flapping Issues ({len(issues)}):")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Detect network interface link flapping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Monitor for 10 seconds (default)
  %(prog)s -d 60                        # Monitor for 60 seconds
  %(prog)s -I eth0                      # Check specific interface
  %(prog)s --format json                # Output in JSON format
  %(prog)s --threshold 4                # Alert on 4+ carrier changes
  %(prog)s -w                           # Only output if flapping detected

Common causes of link flapping:
  - Failing or damaged network cables
  - Bad SFP/QSFP transceivers
  - Faulty switch ports
  - Auto-negotiation failures
  - Power supply issues
  - Driver bugs

Remediation:
  - Replace cables and transceivers
  - Try a different switch port
  - Force speed/duplex settings (disable auto-negotiation)
  - Check for electromagnetic interference
  - Update network drivers and firmware

Exit codes:
  0 - No flapping detected
  1 - Link flapping detected
  2 - Missing /sys filesystem or usage error
        """
    )

    parser.add_argument(
        "-d", "--duration",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Monitoring duration in seconds (default: %(default)s)"
    )

    parser.add_argument(
        "-p", "--poll-interval",
        type=float,
        default=0.1,
        metavar="SECONDS",
        help="Polling interval when kernel counter unavailable (default: %(default)s)"
    )

    parser.add_argument(
        "-I", "--interface",
        metavar="IFACE",
        help="Specific interface to check (default: all interfaces)"
    )

    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=2,
        metavar="COUNT",
        help="Carrier changes threshold for flapping alert (default: %(default)s)"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed transition information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if flapping is detected"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.duration <= 0:
        print("Error: Duration must be positive", file=sys.stderr)
        sys.exit(2)

    if args.poll_interval <= 0:
        print("Error: Poll interval must be positive", file=sys.stderr)
        sys.exit(2)

    if args.threshold < 1:
        print("Error: Threshold must be at least 1", file=sys.stderr)
        sys.exit(2)

    # Get interface list
    if args.interface:
        interfaces = [args.interface]
        # Verify interface exists
        if not os.path.exists(f'/sys/class/net/{args.interface}'):
            print(f"Error: Interface '{args.interface}' not found", file=sys.stderr)
            sys.exit(2)
    else:
        interfaces = get_interface_list()
        if interfaces is None:
            print("Error: Cannot read /sys/class/net", file=sys.stderr)
            print("This script requires access to /sys filesystem", file=sys.stderr)
            sys.exit(2)

        if not interfaces:
            print("No network interfaces found", file=sys.stderr)
            sys.exit(2)

    # Analyze interfaces
    results, issues = analyze_flapping(
        interfaces,
        args.duration,
        args.poll_interval,
        args.threshold
    )

    # Output results
    if args.format == "json":
        output_json(results, issues, args.duration)
    elif args.format == "table":
        output_table(results, issues, args.warn_only)
    else:
        output_plain(results, issues, args.duration, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
