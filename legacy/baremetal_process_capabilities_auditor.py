#!/usr/bin/env python3
"""
Audit Linux process capabilities for security monitoring.

Scans running processes to identify those with elevated capabilities beyond
standard user permissions. Essential for security audits in large-scale
baremetal environments where privilege escalation risks must be monitored.

Capabilities checked include:
- CAP_SYS_ADMIN (broad system administration)
- CAP_NET_ADMIN (network configuration)
- CAP_NET_RAW (raw socket access)
- CAP_DAC_OVERRIDE (bypass file permissions)
- CAP_SETUID/CAP_SETGID (change process credentials)
- And all other Linux capabilities

Exit codes:
    0 - No unexpected privileged processes found
    1 - Processes with elevated capabilities detected
    2 - Usage error or missing dependency
"""

import argparse
import os
import sys
import json


# Linux capability definitions (from linux/capability.h)
# Capability bit positions
CAPABILITIES = {
    0: 'CAP_CHOWN',
    1: 'CAP_DAC_OVERRIDE',
    2: 'CAP_DAC_READ_SEARCH',
    3: 'CAP_FOWNER',
    4: 'CAP_FSETID',
    5: 'CAP_KILL',
    6: 'CAP_SETGID',
    7: 'CAP_SETUID',
    8: 'CAP_SETPCAP',
    9: 'CAP_LINUX_IMMUTABLE',
    10: 'CAP_NET_BIND_SERVICE',
    11: 'CAP_NET_BROADCAST',
    12: 'CAP_NET_ADMIN',
    13: 'CAP_NET_RAW',
    14: 'CAP_IPC_LOCK',
    15: 'CAP_IPC_OWNER',
    16: 'CAP_SYS_MODULE',
    17: 'CAP_SYS_RAWIO',
    18: 'CAP_SYS_CHROOT',
    19: 'CAP_SYS_PTRACE',
    20: 'CAP_SYS_PACCT',
    21: 'CAP_SYS_ADMIN',
    22: 'CAP_SYS_BOOT',
    23: 'CAP_SYS_NICE',
    24: 'CAP_SYS_RESOURCE',
    25: 'CAP_SYS_TIME',
    26: 'CAP_SYS_TTY_CONFIG',
    27: 'CAP_MKNOD',
    28: 'CAP_LEASE',
    29: 'CAP_AUDIT_WRITE',
    30: 'CAP_AUDIT_CONTROL',
    31: 'CAP_SETFCAP',
    32: 'CAP_MAC_OVERRIDE',
    33: 'CAP_MAC_ADMIN',
    34: 'CAP_SYSLOG',
    35: 'CAP_WAKE_ALARM',
    36: 'CAP_BLOCK_SUSPEND',
    37: 'CAP_AUDIT_READ',
    38: 'CAP_PERFMON',
    39: 'CAP_BPF',
    40: 'CAP_CHECKPOINT_RESTORE',
}

# High-risk capabilities that warrant attention
HIGH_RISK_CAPS = {
    'CAP_SYS_ADMIN',      # Broad system administration
    'CAP_NET_ADMIN',       # Network configuration
    'CAP_NET_RAW',         # Raw socket access
    'CAP_DAC_OVERRIDE',    # Bypass file permissions
    'CAP_DAC_READ_SEARCH', # Bypass file read permissions
    'CAP_SETUID',          # Change UID
    'CAP_SETGID',          # Change GID
    'CAP_SYS_PTRACE',      # Trace any process
    'CAP_SYS_MODULE',      # Load kernel modules
    'CAP_SYS_RAWIO',       # Raw I/O access
    'CAP_CHOWN',           # Change file ownership
    'CAP_FOWNER',          # Bypass ownership checks
    'CAP_SETPCAP',         # Modify process capabilities
    'CAP_BPF',             # BPF operations
}


def parse_capability_hex(hex_str):
    """Parse capability hex string to list of capability names."""
    try:
        cap_bits = int(hex_str, 16)
    except ValueError:
        return []

    caps = []
    for bit, name in CAPABILITIES.items():
        if cap_bits & (1 << bit):
            caps.append(name)

    return caps


def get_process_list():
    """Get list of all process PIDs from /proc."""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except OSError:
        pass
    return pids


def get_process_info(pid):
    """Get process information including capabilities."""
    info = {
        'pid': pid,
        'comm': None,
        'cmdline': None,
        'uid': None,
        'user': None,
        'cap_effective': [],
        'cap_permitted': [],
        'cap_inheritable': [],
        'cap_bounding': [],
        'cap_ambient': [],
    }

    # Get process name
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            info['comm'] = f.read().strip()
    except (IOError, OSError):
        return None

    # Get command line
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            info['cmdline'] = cmdline[:200] if cmdline else info['comm']
    except (IOError, OSError):
        info['cmdline'] = info['comm']

    # Get UID and capabilities from status
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Uid:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['uid'] = int(parts[1])
                elif line.startswith('CapEff:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['cap_effective'] = parse_capability_hex(parts[1])
                elif line.startswith('CapPrm:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['cap_permitted'] = parse_capability_hex(parts[1])
                elif line.startswith('CapInh:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['cap_inheritable'] = parse_capability_hex(parts[1])
                elif line.startswith('CapBnd:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['cap_bounding'] = parse_capability_hex(parts[1])
                elif line.startswith('CapAmb:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['cap_ambient'] = parse_capability_hex(parts[1])
    except (IOError, OSError):
        return None

    # Get username
    if info['uid'] is not None:
        try:
            import pwd
            info['user'] = pwd.getpwuid(info['uid']).pw_name
        except (KeyError, ImportError):
            info['user'] = str(info['uid'])

    return info


def analyze_process(proc_info, include_root=False, cap_filter=None):
    """Analyze process capabilities and return findings."""
    if proc_info is None:
        return None

    # Skip root processes unless explicitly included
    if not include_root and proc_info['uid'] == 0:
        return None

    # Get effective capabilities (what the process can actually do)
    effective_caps = set(proc_info['cap_effective'])

    # If no capabilities, skip
    if not effective_caps:
        return None

    # Filter by specific capability if requested
    if cap_filter:
        if cap_filter not in effective_caps:
            return None

    # Identify high-risk capabilities
    high_risk = effective_caps & HIGH_RISK_CAPS

    return {
        'pid': proc_info['pid'],
        'comm': proc_info['comm'],
        'cmdline': proc_info['cmdline'],
        'uid': proc_info['uid'],
        'user': proc_info['user'],
        'effective_caps': sorted(effective_caps),
        'permitted_caps': sorted(proc_info['cap_permitted']),
        'inheritable_caps': sorted(proc_info['cap_inheritable']),
        'ambient_caps': sorted(proc_info['cap_ambient']),
        'high_risk_caps': sorted(high_risk),
        'cap_count': len(effective_caps),
        'high_risk_count': len(high_risk),
    }


def collect_privileged_processes(include_root=False, cap_filter=None,
                                  user_filter=None, comm_filter=None,
                                  high_risk_only=False):
    """Collect all processes with elevated capabilities."""
    results = []

    for pid in get_process_list():
        proc_info = get_process_info(pid)
        if proc_info is None:
            continue

        # Apply user filter
        if user_filter and proc_info['user'] != user_filter:
            continue

        # Apply comm filter
        if comm_filter and comm_filter.lower() not in proc_info['comm'].lower():
            continue

        analysis = analyze_process(proc_info, include_root, cap_filter)
        if analysis is None:
            continue

        # Apply high-risk only filter
        if high_risk_only and not analysis['high_risk_caps']:
            continue

        results.append(analysis)

    # Sort by high-risk count, then total cap count
    results.sort(key=lambda x: (-x['high_risk_count'], -x['cap_count']))

    return results


def generate_summary(processes):
    """Generate summary statistics."""
    if not processes:
        return {
            'total_privileged_processes': 0,
            'processes_with_high_risk': 0,
            'unique_capabilities_found': 0,
            'unique_high_risk_caps': 0,
            'most_common_caps': [],
        }

    all_caps = []
    high_risk_caps = []
    for p in processes:
        all_caps.extend(p['effective_caps'])
        high_risk_caps.extend(p['high_risk_caps'])

    # Count capability frequency
    cap_counts = {}
    for cap in all_caps:
        cap_counts[cap] = cap_counts.get(cap, 0) + 1

    most_common = sorted(cap_counts.items(), key=lambda x: -x[1])[:10]

    return {
        'total_privileged_processes': len(processes),
        'processes_with_high_risk': sum(1 for p in processes if p['high_risk_caps']),
        'unique_capabilities_found': len(set(all_caps)),
        'unique_high_risk_caps': len(set(high_risk_caps)),
        'most_common_caps': [{'cap': cap, 'count': count} for cap, count in most_common],
    }


def output_plain(processes, summary, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if warn_only and summary['processes_with_high_risk'] == 0:
        print("No high-risk privileged processes found.")
        return

    print("Process Capabilities Audit")
    print("=" * 70)
    print(f"Privileged processes found: {summary['total_privileged_processes']}")
    print(f"Processes with high-risk caps: {summary['processes_with_high_risk']}")
    print(f"Unique capabilities found: {summary['unique_capabilities_found']}")
    print()

    if summary['most_common_caps']:
        print("Most common capabilities:")
        for item in summary['most_common_caps'][:5]:
            risk_marker = " [HIGH RISK]" if item['cap'] in HIGH_RISK_CAPS else ""
            print(f"  {item['cap']}: {item['count']} processes{risk_marker}")
        print()

    if processes:
        print("Privileged Processes:")
        print("-" * 70)

        for proc in processes:
            risk_str = ""
            if proc['high_risk_caps']:
                risk_str = f" [!] HIGH RISK: {len(proc['high_risk_caps'])} caps"

            print(f"PID {proc['pid']}: {proc['comm']} (user: {proc['user']}){risk_str}")
            print(f"  Effective caps ({proc['cap_count']}): {', '.join(proc['effective_caps'][:5])}")
            if len(proc['effective_caps']) > 5:
                print(f"    ... and {len(proc['effective_caps']) - 5} more")

            if verbose:
                if proc['cmdline'] and proc['cmdline'] != proc['comm']:
                    print(f"  Command: {proc['cmdline'][:60]}...")
                if proc['high_risk_caps']:
                    print(f"  High-risk: {', '.join(proc['high_risk_caps'])}")

            print()


def output_json(processes, summary):
    """Output results in JSON format."""
    output = {
        'summary': summary,
        'processes': processes,
        'high_risk_capabilities': sorted(HIGH_RISK_CAPS),
    }
    print(json.dumps(output, indent=2))


def output_table(processes, summary, warn_only=False):
    """Output results in table format."""
    if warn_only and summary['processes_with_high_risk'] == 0:
        print("No high-risk privileged processes found.")
        return

    print("=" * 90)
    print("PROCESS CAPABILITIES AUDIT")
    print("=" * 90)
    print()

    print(f"{'Metric':<40} {'Value':<20}")
    print("-" * 60)
    print(f"{'Privileged processes':<40} {summary['total_privileged_processes']:<20}")
    print(f"{'With high-risk capabilities':<40} {summary['processes_with_high_risk']:<20}")
    print(f"{'Unique capabilities found':<40} {summary['unique_capabilities_found']:<20}")
    print()

    if processes:
        print("=" * 90)
        print(f"{'PID':<8} {'Process':<20} {'User':<12} {'Caps':<6} {'Risk':<6} {'High-Risk Capabilities'}")
        print("-" * 90)

        for proc in processes:
            high_risk_str = ', '.join(proc['high_risk_caps'][:3])
            if len(proc['high_risk_caps']) > 3:
                high_risk_str += f"... (+{len(proc['high_risk_caps']) - 3})"

            print(f"{proc['pid']:<8} {proc['comm'][:20]:<20} {proc['user'][:12]:<12} "
                  f"{proc['cap_count']:<6} {proc['high_risk_count']:<6} {high_risk_str}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit Linux process capabilities for security monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Show non-root processes with capabilities
  %(prog)s --include-root       # Include root processes
  %(prog)s --high-risk-only     # Only show processes with high-risk caps
  %(prog)s --cap CAP_NET_RAW    # Find processes with specific capability
  %(prog)s --user nginx         # Filter by user
  %(prog)s --format json        # JSON output for automation

High-risk capabilities include:
  CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_DAC_OVERRIDE,
  CAP_SETUID, CAP_SETGID, CAP_SYS_PTRACE, CAP_SYS_MODULE, etc.

Exit codes:
  0 - No privileged processes with high-risk capabilities found
  1 - Processes with elevated capabilities detected
  2 - Usage error or missing dependency

Notes:
  By default, root processes are excluded since they have full capabilities.
  Use --include-root to audit all processes including root.
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
        help='Show detailed information including command lines'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only produce output if high-risk capabilities found'
    )

    parser.add_argument(
        '--include-root',
        action='store_true',
        help='Include root processes (uid 0) in analysis'
    )

    parser.add_argument(
        '--high-risk-only',
        action='store_true',
        help='Only show processes with high-risk capabilities'
    )

    parser.add_argument(
        '--cap',
        metavar='CAPABILITY',
        help='Filter by specific capability (e.g., CAP_NET_RAW)'
    )

    parser.add_argument(
        '-u', '--user',
        help='Filter by username'
    )

    parser.add_argument(
        '-c', '--comm',
        help='Filter by process name pattern'
    )

    parser.add_argument(
        '--list-caps',
        action='store_true',
        help='List all known capabilities and exit'
    )

    args = parser.parse_args()

    # Handle --list-caps
    if args.list_caps:
        print("Linux Capabilities:")
        print("-" * 50)
        for bit, name in sorted(CAPABILITIES.items()):
            risk = " [HIGH RISK]" if name in HIGH_RISK_CAPS else ""
            print(f"  {bit:2d}: {name}{risk}")
        sys.exit(0)

    # Validate capability filter
    if args.cap:
        cap_upper = args.cap.upper()
        if not cap_upper.startswith('CAP_'):
            cap_upper = 'CAP_' + cap_upper
        if cap_upper not in CAPABILITIES.values():
            print(f"Error: Unknown capability '{args.cap}'", file=sys.stderr)
            print("Use --list-caps to see available capabilities", file=sys.stderr)
            sys.exit(2)
        args.cap = cap_upper

    # Check for /proc filesystem
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not accessible", file=sys.stderr)
        print("This tool requires Linux with procfs mounted", file=sys.stderr)
        sys.exit(2)

    # Collect data
    processes = collect_privileged_processes(
        include_root=args.include_root,
        cap_filter=args.cap,
        user_filter=args.user,
        comm_filter=args.comm,
        high_risk_only=args.high_risk_only,
    )

    summary = generate_summary(processes)

    # Handle warn-only
    if args.warn_only and summary['processes_with_high_risk'] == 0:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(processes, summary)
    elif args.format == 'table':
        output_table(processes, summary, args.warn_only)
    else:
        output_plain(processes, summary, args.verbose, args.warn_only)

    # Exit code based on findings
    if summary['processes_with_high_risk'] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
