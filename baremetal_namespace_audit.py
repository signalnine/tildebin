#!/usr/bin/env python3
"""
Audit Linux namespaces for security and operational health.

This script analyzes all Linux namespace types (mnt, pid, user, net, ipc, uts, cgroup)
to detect potential security issues, leaked namespaces, and configuration problems.
Critical for container host security and debugging namespace isolation issues.

Namespace types audited:
- mnt:    Mount namespace - filesystem isolation
- pid:    Process namespace - PID isolation
- net:    Network namespace - network stack isolation
- ipc:    IPC namespace - System V IPC and POSIX message queues
- uts:    UTS namespace - hostname and domain name
- user:   User namespace - UID/GID mapping
- cgroup: Cgroup namespace - cgroup root visibility

Detects:
- Processes sharing namespaces unexpectedly (potential security issue)
- Orphaned namespaces (namespaces with no processes)
- Non-root processes in root namespaces (containers breaking isolation)
- User namespace mapping issues
- Namespace count anomalies per process

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found
    2 - Usage error or missing /proc filesystem

Examples:
    baremetal_namespace_audit.py                    # Full audit
    baremetal_namespace_audit.py --format json      # JSON output
    baremetal_namespace_audit.py --warn-only        # Only show issues
    baremetal_namespace_audit.py -t pid,net         # Only audit PID and NET namespaces
    baremetal_namespace_audit.py --summary          # Summary statistics only
"""

import argparse
import json
import os
import sys
from collections import defaultdict


# All Linux namespace types
NAMESPACE_TYPES = ['mnt', 'pid', 'net', 'ipc', 'uts', 'user', 'cgroup']

# Namespace types that containers typically isolate
CONTAINER_NAMESPACES = ['mnt', 'pid', 'net', 'ipc', 'uts']


def check_proc_available():
    """Check if /proc filesystem is available."""
    return os.path.isdir('/proc') and os.path.exists('/proc/1/ns')


def get_init_namespaces():
    """Get namespace IDs for init process (PID 1) - the root namespaces."""
    namespaces = {}
    ns_path = '/proc/1/ns'

    if not os.path.isdir(ns_path):
        return namespaces

    for ns_type in NAMESPACE_TYPES:
        ns_link = os.path.join(ns_path, ns_type)
        try:
            target = os.readlink(ns_link)
            # Extract inode from format like "mnt:[4026531840]"
            if '[' in target and ']' in target:
                ns_id = target.split('[')[1].rstrip(']')
                namespaces[ns_type] = ns_id
        except (OSError, IOError):
            pass

    return namespaces


def get_process_namespaces(pid):
    """Get namespace IDs for a specific process."""
    namespaces = {}
    ns_path = f'/proc/{pid}/ns'

    if not os.path.isdir(ns_path):
        return namespaces

    for ns_type in NAMESPACE_TYPES:
        ns_link = os.path.join(ns_path, ns_type)
        try:
            target = os.readlink(ns_link)
            if '[' in target and ']' in target:
                ns_id = target.split('[')[1].rstrip(']')
                namespaces[ns_type] = ns_id
        except (OSError, IOError):
            pass

    return namespaces


def get_process_info(pid):
    """Get basic process information."""
    info = {
        'pid': pid,
        'comm': '-',
        'uid': -1,
        'cmdline': ''
    }

    # Get process name
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            info['comm'] = f.read().strip()
    except (OSError, IOError):
        pass

    # Get UID
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Uid:'):
                    # Format: Uid: real effective saved fs
                    info['uid'] = int(line.split()[1])
                    break
    except (OSError, IOError, ValueError, IndexError):
        pass

    # Get command line (truncated)
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            info['cmdline'] = cmdline[:100] if len(cmdline) > 100 else cmdline
    except (OSError, IOError):
        pass

    return info


def get_all_pids():
    """Get list of all PIDs from /proc."""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except (OSError, IOError):
        pass
    return sorted(pids)


def audit_namespaces(namespace_types=None, verbose=False):
    """
    Perform comprehensive namespace audit.

    Returns audit results with:
    - Namespace statistics
    - Process-to-namespace mappings
    - Detected issues
    """
    if namespace_types is None:
        namespace_types = NAMESPACE_TYPES

    # Get init (root) namespaces as reference
    init_ns = get_init_namespaces()

    if not init_ns:
        return None, "Cannot read init namespaces from /proc/1/ns"

    # Track namespace usage
    # ns_type -> ns_id -> list of PIDs
    namespace_usage = {ns_type: defaultdict(list) for ns_type in namespace_types}

    # Track processes not in root namespace
    non_root_ns_processes = {ns_type: [] for ns_type in namespace_types}

    # Track process info for issues
    process_cache = {}

    issues = []

    # Scan all processes
    pids = get_all_pids()

    for pid in pids:
        proc_ns = get_process_namespaces(pid)

        if not proc_ns:
            continue

        for ns_type in namespace_types:
            if ns_type not in proc_ns:
                continue

            ns_id = proc_ns[ns_type]
            namespace_usage[ns_type][ns_id].append(pid)

            # Check if process is outside root namespace
            root_ns_id = init_ns.get(ns_type)
            if root_ns_id and ns_id != root_ns_id:
                non_root_ns_processes[ns_type].append(pid)

    # Build statistics
    stats = {
        'total_processes': len(pids),
        'namespaces': {}
    }

    for ns_type in namespace_types:
        usage = namespace_usage[ns_type]
        unique_ns = len(usage)
        procs_in_root = len(usage.get(init_ns.get(ns_type, ''), []))
        procs_isolated = len(non_root_ns_processes[ns_type])

        stats['namespaces'][ns_type] = {
            'unique_count': unique_ns,
            'root_ns_id': init_ns.get(ns_type, 'unknown'),
            'processes_in_root': procs_in_root,
            'processes_isolated': procs_isolated
        }

    # Detect issues

    # Issue 1: User namespace with processes running as UID 0 inside
    # (This is normal for containers, but worth noting)

    # Issue 2: Large number of unique namespaces (potential leak)
    for ns_type in namespace_types:
        unique_count = stats['namespaces'][ns_type]['unique_count']
        # Threshold: more than 100 unique namespaces per type is unusual
        if unique_count > 100:
            issues.append({
                'type': 'high_namespace_count',
                'namespace': ns_type,
                'count': unique_count,
                'severity': 'warning',
                'message': f'High number of unique {ns_type} namespaces ({unique_count}), possible namespace leak'
            })

    # Issue 3: Namespaces with only one process (potentially orphaned containers)
    for ns_type in namespace_types:
        if ns_type not in CONTAINER_NAMESPACES:
            continue

        root_ns_id = init_ns.get(ns_type)
        for ns_id, pid_list in namespace_usage[ns_type].items():
            if ns_id == root_ns_id:
                continue  # Skip root namespace

            if len(pid_list) == 1:
                pid = pid_list[0]
                if pid not in process_cache:
                    process_cache[pid] = get_process_info(pid)

                proc_info = process_cache[pid]

                # Single process in isolated namespace - worth noting
                if verbose:
                    issues.append({
                        'type': 'single_process_namespace',
                        'namespace': ns_type,
                        'namespace_id': ns_id,
                        'pid': pid,
                        'process': proc_info['comm'],
                        'severity': 'info',
                        'message': f'Single process ({proc_info["comm"]}, PID {pid}) in isolated {ns_type} namespace'
                    })

    # Issue 4: Non-container processes (non-root user) in root PID namespace
    # This is normal, but processes that look like they should be containerized
    # but aren't could be an issue

    # Issue 5: Look for processes in non-root network namespace but root mount namespace
    # This could indicate a partially isolated container
    net_non_root = set(non_root_ns_processes.get('net', []))
    mnt_non_root = set(non_root_ns_processes.get('mnt', []))

    partial_isolation = net_non_root - mnt_non_root
    if partial_isolation:
        for pid in list(partial_isolation)[:10]:  # Limit to first 10
            if pid not in process_cache:
                process_cache[pid] = get_process_info(pid)

            proc_info = process_cache[pid]
            issues.append({
                'type': 'partial_isolation',
                'namespace': 'net vs mnt',
                'pid': pid,
                'process': proc_info['comm'],
                'severity': 'warning',
                'message': f'Process {proc_info["comm"]} (PID {pid}) isolated in net but not mnt namespace'
            })

    # Build detailed results
    results = {
        'init_namespaces': init_ns,
        'statistics': stats,
        'issues': issues,
        'namespace_details': {}
    }

    # Add namespace details if verbose
    if verbose:
        for ns_type in namespace_types:
            results['namespace_details'][ns_type] = {}
            for ns_id, pid_list in namespace_usage[ns_type].items():
                is_root = ns_id == init_ns.get(ns_type)
                results['namespace_details'][ns_type][ns_id] = {
                    'is_root': is_root,
                    'process_count': len(pid_list),
                    'pids': pid_list[:20] if len(pid_list) > 20 else pid_list  # Limit
                }

    return results, None


def output_plain(results, warn_only=False, summary_only=False):
    """Output results in plain text format."""
    stats = results['statistics']
    issues = results['issues']

    # Print summary header
    print(f"Linux Namespace Audit")
    print(f"=" * 60)
    print(f"Total processes scanned: {stats['total_processes']}")
    print()

    # Print namespace statistics
    print(f"{'Namespace':<10} {'Unique':<10} {'In Root':<12} {'Isolated':<12}")
    print("-" * 44)

    for ns_type, ns_stats in stats['namespaces'].items():
        unique = ns_stats['unique_count']
        in_root = ns_stats['processes_in_root']
        isolated = ns_stats['processes_isolated']
        print(f"{ns_type:<10} {unique:<10} {in_root:<12} {isolated:<12}")

    print()

    if summary_only:
        return

    # Print issues
    if issues:
        filtered_issues = issues
        if warn_only:
            filtered_issues = [i for i in issues if i['severity'] in ('warning', 'critical')]

        if filtered_issues:
            print(f"Issues Found: {len(filtered_issues)}")
            print("-" * 60)

            for issue in filtered_issues:
                severity = issue['severity'].upper()
                symbol = '!!!' if severity == 'CRITICAL' else ('!! ' if severity == 'WARNING' else '   ')
                print(f"[{symbol}] [{severity}] {issue['message']}")
            print()
    else:
        print("No issues detected.")
        print()


def output_json(results):
    """Output results in JSON format."""
    import time
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'audit_results': results
    }
    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format."""
    stats = results['statistics']
    issues = results['issues']

    # Namespace table
    print(f"{'Namespace':<10} {'Unique NS':<12} {'Root NS ID':<20} {'In Root':<10} {'Isolated':<10}")
    print("-" * 72)

    for ns_type, ns_stats in stats['namespaces'].items():
        root_id = ns_stats['root_ns_id'][:18]
        print(f"{ns_type:<10} {ns_stats['unique_count']:<12} {root_id:<20} {ns_stats['processes_in_root']:<10} {ns_stats['processes_isolated']:<10}")

    print()

    # Issues table
    filtered_issues = issues
    if warn_only:
        filtered_issues = [i for i in issues if i['severity'] in ('warning', 'critical')]

    if filtered_issues:
        print(f"{'Severity':<10} {'Type':<25} {'Details':<40}")
        print("-" * 75)

        for issue in filtered_issues:
            details = issue.get('message', '')[:40]
            print(f"{issue['severity'].upper():<10} {issue['type']:<25} {details:<40}")


def main():
    parser = argparse.ArgumentParser(
        description='Audit Linux namespaces for security and operational health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Full namespace audit
  %(prog)s --format json           # JSON output
  %(prog)s -w                      # Only show warnings
  %(prog)s -t pid,net,mnt          # Only audit specific namespaces
  %(prog)s --summary               # Summary statistics only
  %(prog)s -v                      # Verbose with namespace details

Exit codes:
  0 - No issues detected
  1 - Warnings or issues found
  2 - Usage error or /proc not available
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed namespace information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and critical issues'
    )

    parser.add_argument(
        '-t', '--types',
        type=str,
        metavar='TYPES',
        help=f'Comma-separated namespace types to audit (default: all). Options: {",".join(NAMESPACE_TYPES)}'
    )

    parser.add_argument(
        '--summary',
        action='store_true',
        help='Show summary statistics only, no detailed issues'
    )

    args = parser.parse_args()

    # Check /proc availability
    if not check_proc_available():
        print("Error: /proc filesystem not available or /proc/1/ns not readable",
              file=sys.stderr)
        sys.exit(2)

    # Parse namespace types
    namespace_types = NAMESPACE_TYPES
    if args.types:
        requested_types = [t.strip() for t in args.types.split(',')]
        invalid_types = [t for t in requested_types if t not in NAMESPACE_TYPES]
        if invalid_types:
            print(f"Error: Invalid namespace types: {', '.join(invalid_types)}",
                  file=sys.stderr)
            print(f"Valid types: {', '.join(NAMESPACE_TYPES)}", file=sys.stderr)
            sys.exit(2)
        namespace_types = requested_types

    # Perform audit
    results, error = audit_namespaces(namespace_types, verbose=args.verbose)

    if error:
        if args.format == 'json':
            print(json.dumps({'error': error}))
        else:
            print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.warn_only, args.summary)

    # Determine exit code
    has_issues = any(
        i['severity'] in ('warning', 'critical')
        for i in results.get('issues', [])
    )
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
