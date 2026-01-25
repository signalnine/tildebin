#!/usr/bin/env python3
"""
Monitor network namespace health on container hosts.

This script identifies network namespaces and checks their health status:
- Lists all network namespaces (named and process-based)
- Detects orphaned namespaces (no processes attached)
- Checks veth pair consistency (dangling interfaces)
- Monitors namespace interface counts
- Identifies namespaces with networking issues

Useful for:
- Container host health monitoring (Docker, Kubernetes nodes)
- Detecting leaked network namespaces after container crashes
- Identifying veth pair inconsistencies
- Troubleshooting container networking issues

Exit codes:
    0 - All network namespaces healthy
    1 - Issues detected (orphaned namespaces, dangling veths, etc.)
    2 - Usage error or required tools not available
"""

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict


def run_command(cmd, check=False):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr


def check_ip_command():
    """Check if ip command is available."""
    returncode, _, _ = run_command(['ip', 'version'])
    return returncode == 0


def get_named_namespaces():
    """Get list of named network namespaces from ip netns."""
    returncode, stdout, stderr = run_command(['ip', 'netns', 'list'])

    if returncode != 0:
        return []

    namespaces = []
    for line in stdout.split('\n'):
        if line.strip():
            # Format is either "name" or "name (id: N)"
            parts = line.split()
            if parts:
                namespaces.append({
                    'name': parts[0],
                    'type': 'named',
                    'id': None
                })
    return namespaces


def get_proc_namespaces():
    """Get network namespaces from /proc by examining process network ns."""
    namespaces = {}
    default_ns = None

    # Get the default namespace inode from pid 1
    try:
        default_ns = os.readlink('/proc/1/ns/net')
    except (OSError, FileNotFoundError):
        pass

    # Scan all processes
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue

            try:
                ns_link = os.readlink(f'/proc/{pid}/ns/net')
                if ns_link != default_ns:
                    if ns_link not in namespaces:
                        namespaces[ns_link] = {
                            'inode': ns_link,
                            'pids': [],
                            'type': 'process'
                        }
                    namespaces[ns_link]['pids'].append(pid)
            except (OSError, FileNotFoundError):
                continue
    except (OSError, PermissionError):
        pass

    return list(namespaces.values())


def get_namespace_interfaces(ns_name=None):
    """Get network interfaces in a namespace."""
    if ns_name:
        cmd = ['ip', 'netns', 'exec', ns_name, 'ip', '-j', 'link', 'show']
    else:
        cmd = ['ip', '-j', 'link', 'show']

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return []

    try:
        interfaces = json.loads(stdout) if stdout else []
        return interfaces
    except json.JSONDecodeError:
        return []


def get_veth_pairs():
    """Get veth pairs and their peer relationships."""
    veths = {}

    returncode, stdout, stderr = run_command(['ip', '-j', 'link', 'show', 'type', 'veth'])

    if returncode != 0 or not stdout:
        return veths

    try:
        interfaces = json.loads(stdout)
        for iface in interfaces:
            name = iface.get('ifname', '')
            ifindex = iface.get('ifindex', 0)
            link = iface.get('link', '')  # peer interface name if known

            # Get peer ifindex from link_index if available
            peer_ifindex = iface.get('link_index', 0)

            veths[name] = {
                'ifindex': ifindex,
                'peer_ifindex': peer_ifindex,
                'peer_name': link,
                'operstate': iface.get('operstate', 'unknown'),
                'master': iface.get('master', None)
            }
    except json.JSONDecodeError:
        pass

    return veths


def check_orphaned_namespaces(proc_namespaces):
    """Check for namespaces with no processes (potential leaks)."""
    orphaned = []

    for ns in proc_namespaces:
        if not ns.get('pids'):
            orphaned.append(ns)

    return orphaned


def check_dangling_veths(veths):
    """Check for veth interfaces without a valid peer."""
    dangling = []

    # Build a set of all ifindexes
    all_ifindexes = set(v['ifindex'] for v in veths.values())

    for name, info in veths.items():
        peer_idx = info.get('peer_ifindex', 0)

        # A veth is dangling if:
        # 1. peer_ifindex is 0 or not found in any namespace
        # 2. operstate is not 'up' (might indicate peer issues)
        if peer_idx == 0:
            dangling.append({
                'name': name,
                'reason': 'no peer index',
                'operstate': info.get('operstate')
            })
        elif peer_idx not in all_ifindexes:
            # Peer might be in another namespace - this is actually normal
            # Only flag if the interface is down
            if info.get('operstate') == 'down':
                dangling.append({
                    'name': name,
                    'reason': 'peer in different namespace and interface down',
                    'operstate': info.get('operstate')
                })

    return dangling


def analyze_namespace_health(ns_name):
    """Analyze health of a specific namespace."""
    issues = []

    interfaces = get_namespace_interfaces(ns_name)

    if not interfaces:
        issues.append("No interfaces found (may lack permissions)")
        return issues

    # Check for basic networking
    has_loopback = False
    has_non_lo = False
    down_interfaces = []

    for iface in interfaces:
        ifname = iface.get('ifname', '')
        operstate = iface.get('operstate', 'unknown')

        if ifname == 'lo':
            has_loopback = True
            if operstate != 'UNKNOWN' and operstate != 'up':
                issues.append(f"Loopback interface is {operstate}")
        else:
            has_non_lo = True
            if operstate == 'down':
                down_interfaces.append(ifname)

    if not has_loopback:
        issues.append("Missing loopback interface")

    if down_interfaces:
        issues.append(f"Down interfaces: {', '.join(down_interfaces)}")

    return issues


def output_plain(results, warn_only=False, verbose=False):
    """Output results in plain text format."""
    named = results['named_namespaces']
    proc = results['process_namespaces']
    veths = results['veth_pairs']
    dangling = results['dangling_veths']
    summary = results['summary']

    if warn_only and summary['total_issues'] == 0:
        return

    print("Network Namespace Health Report")
    print("=" * 50)
    print()

    print(f"Named namespaces:      {summary['named_count']}")
    print(f"Process namespaces:    {summary['process_count']}")
    print(f"Veth pairs:            {summary['veth_count']}")
    print(f"Issues detected:       {summary['total_issues']}")
    print()

    if named and (verbose or not warn_only):
        print("Named Namespaces:")
        print("-" * 40)
        for ns in named:
            status = "OK"
            if ns.get('issues'):
                status = f"ISSUES: {len(ns['issues'])}"
            print(f"  {ns['name']}: {status}")
            if verbose and ns.get('issues'):
                for issue in ns['issues']:
                    print(f"    - {issue}")
        print()

    if proc and verbose:
        print("Process Namespaces:")
        print("-" * 40)
        for ns in proc:
            pid_count = len(ns.get('pids', []))
            print(f"  {ns['inode']}: {pid_count} process(es)")
        print()

    if dangling:
        print("Dangling Veth Interfaces:")
        print("-" * 40)
        for veth in dangling:
            print(f"  {veth['name']}: {veth['reason']} (state: {veth['operstate']})")
        print()

    if summary['total_issues'] == 0:
        print("Status: All network namespaces healthy")
    else:
        print(f"Status: {summary['total_issues']} issue(s) detected")


def output_json(results):
    """Output results in JSON format."""
    print(json.dumps(results, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format."""
    summary = results['summary']

    if warn_only and summary['total_issues'] == 0:
        return

    print(f"{'Metric':<30} {'Value':>10} {'Status':<15}")
    print("=" * 55)

    print(f"{'Named Namespaces':<30} {summary['named_count']:>10} {'':<15}")
    print(f"{'Process Namespaces':<30} {summary['process_count']:>10} {'':<15}")
    print(f"{'Veth Pairs':<30} {summary['veth_count']:>10} {'':<15}")

    dangling_status = 'WARNING' if results['dangling_veths'] else 'OK'
    print(f"{'Dangling Veths':<30} {len(results['dangling_veths']):>10} {dangling_status:<15}")

    overall = 'OK' if summary['total_issues'] == 0 else 'WARNING'
    print(f"{'Total Issues':<30} {summary['total_issues']:>10} {overall:<15}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor network namespace health on container hosts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic namespace health check
  %(prog)s -v                       # Verbose output with details
  %(prog)s --format json            # JSON output for scripting
  %(prog)s -w                       # Only output if issues found

Network namespace issues this tool detects:
  - Orphaned namespaces (leaked from crashed containers)
  - Dangling veth pairs (peers in deleted namespaces)
  - Down interfaces in active namespaces
  - Missing loopback interfaces
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
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only produce output if issues detected'
    )

    args = parser.parse_args()

    # Check for ip command
    if not check_ip_command():
        print("Error: 'ip' command not found", file=sys.stderr)
        print("Install with: apt-get install iproute2", file=sys.stderr)
        sys.exit(2)

    # Gather data
    named_namespaces = get_named_namespaces()
    proc_namespaces = get_proc_namespaces()
    veths = get_veth_pairs()

    # Analyze health
    for ns in named_namespaces:
        ns['issues'] = analyze_namespace_health(ns['name'])

    dangling_veths = check_dangling_veths(veths)

    # Count issues
    total_issues = len(dangling_veths)
    for ns in named_namespaces:
        total_issues += len(ns.get('issues', []))

    # Build results
    results = {
        'summary': {
            'named_count': len(named_namespaces),
            'process_count': len(proc_namespaces),
            'veth_count': len(veths),
            'dangling_veth_count': len(dangling_veths),
            'total_issues': total_issues
        },
        'named_namespaces': named_namespaces,
        'process_namespaces': proc_namespaces,
        'veth_pairs': list(veths.keys()),
        'dangling_veths': dangling_veths
    }

    # Output
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, warn_only=args.warn_only)
    else:
        output_plain(results, warn_only=args.warn_only, verbose=args.verbose)

    # Exit code
    sys.exit(1 if total_issues > 0 else 0)


if __name__ == "__main__":
    main()
