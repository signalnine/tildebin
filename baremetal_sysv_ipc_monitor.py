#!/usr/bin/env python3
"""
Monitor System V IPC resource usage (semaphores, shared memory, message queues).

System V IPC resources are used by many enterprise applications including:
- Databases (PostgreSQL, Oracle, MySQL, SAP HANA)
- Message brokers and middleware
- Legacy enterprise applications
- High-performance computing applications

This script monitors:
- Semaphore arrays and individual semaphores
- Shared memory segments and total usage
- Message queues and queue sizes
- Usage vs kernel limits (from /proc/sys/kernel)

Common failure modes:
- "No space left on device" when semaphore arrays exhausted
- "Cannot allocate memory" for shared memory limits
- Orphaned IPC resources from crashed applications
- Resource leaks over time

Exit codes:
    0 - IPC resource usage is healthy
    1 - High usage or orphaned resources detected
    2 - Missing /proc files, ipcs unavailable, or usage error
"""

import argparse
import sys
import json
import os
import subprocess


def read_proc_value(path):
    """Read a single value from /proc or /sys."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return None


def get_kernel_limits():
    """Get System V IPC kernel limits from /proc/sys/kernel.

    Returns:
        dict: Kernel limits for semaphores, shared memory, and message queues
    """
    limits = {}

    # Semaphore limits (SEMMSL SEMMNS SEMOPM SEMMNI)
    sem_val = read_proc_value('/proc/sys/kernel/sem')
    if sem_val:
        parts = sem_val.split()
        if len(parts) >= 4:
            limits['sem'] = {
                'semmsl': int(parts[0]),  # Max semaphores per array
                'semmns': int(parts[1]),  # Max semaphores system-wide
                'semopm': int(parts[2]),  # Max ops per semop call
                'semmni': int(parts[3]),  # Max semaphore arrays
            }

    # Shared memory limits
    shmmax = read_proc_value('/proc/sys/kernel/shmmax')
    if shmmax:
        limits['shmmax'] = int(shmmax)  # Max segment size

    shmall = read_proc_value('/proc/sys/kernel/shmall')
    if shmall:
        limits['shmall'] = int(shmall)  # Max total pages

    shmmni = read_proc_value('/proc/sys/kernel/shmmni')
    if shmmni:
        limits['shmmni'] = int(shmmni)  # Max segments

    # Message queue limits
    msgmax = read_proc_value('/proc/sys/kernel/msgmax')
    if msgmax:
        limits['msgmax'] = int(msgmax)  # Max message size

    msgmnb = read_proc_value('/proc/sys/kernel/msgmnb')
    if msgmnb:
        limits['msgmnb'] = int(msgmnb)  # Max queue size

    msgmni = read_proc_value('/proc/sys/kernel/msgmni')
    if msgmni:
        limits['msgmni'] = int(msgmni)  # Max queues

    return limits


def run_ipcs(resource_type):
    """Run ipcs command and parse output.

    Args:
        resource_type: 's' for semaphores, 'm' for shared memory, 'q' for queues

    Returns:
        list: List of resource dictionaries, or None on error
    """
    try:
        result = subprocess.run(
            ['ipcs', f'-{resource_type}'],
            capture_output=True,
            text=True,
            check=True
        )
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError:
        return None

    resources = []
    lines = result.stdout.strip().split('\n')

    # Skip header lines (varies by type)
    in_data = False
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect start of data section
        if line.startswith('---'):
            in_data = True
            continue

        if not in_data:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        if resource_type == 's':  # Semaphores
            # key semid owner perms nsems
            if len(parts) >= 5:
                try:
                    resources.append({
                        'key': parts[0],
                        'id': int(parts[1]),
                        'owner': parts[2],
                        'perms': parts[3],
                        'nsems': int(parts[4]) if len(parts) > 4 else 0
                    })
                except (ValueError, IndexError):
                    continue

        elif resource_type == 'm':  # Shared memory
            # key shmid owner perms bytes nattch
            if len(parts) >= 5:
                try:
                    resources.append({
                        'key': parts[0],
                        'id': int(parts[1]),
                        'owner': parts[2],
                        'perms': parts[3],
                        'bytes': int(parts[4]),
                        'nattch': int(parts[5]) if len(parts) > 5 else 0
                    })
                except (ValueError, IndexError):
                    continue

        elif resource_type == 'q':  # Message queues
            # key msqid owner perms used-bytes messages
            if len(parts) >= 5:
                try:
                    resources.append({
                        'key': parts[0],
                        'id': int(parts[1]),
                        'owner': parts[2],
                        'perms': parts[3],
                        'used_bytes': int(parts[4]),
                        'messages': int(parts[5]) if len(parts) > 5 else 0
                    })
                except (ValueError, IndexError):
                    continue

    return resources


def get_ipc_stats():
    """Gather System V IPC statistics.

    Returns:
        dict: IPC statistics including semaphores, shared memory, and queues
    """
    stats = {
        'semaphores': [],
        'shared_memory': [],
        'message_queues': [],
        'limits': get_kernel_limits()
    }

    # Get semaphores
    sems = run_ipcs('s')
    if sems is not None:
        stats['semaphores'] = sems

    # Get shared memory
    shm = run_ipcs('m')
    if shm is not None:
        stats['shared_memory'] = shm

    # Get message queues
    queues = run_ipcs('q')
    if queues is not None:
        stats['message_queues'] = queues

    return stats


def calculate_usage(stats):
    """Calculate usage statistics.

    Args:
        stats: IPC statistics dict

    Returns:
        dict: Usage statistics and percentages
    """
    usage = {}
    limits = stats.get('limits', {})

    # Semaphore usage
    sem_arrays = len(stats.get('semaphores', []))
    total_sems = sum(s.get('nsems', 0) for s in stats.get('semaphores', []))

    sem_limits = limits.get('sem', {})
    usage['semaphores'] = {
        'arrays': sem_arrays,
        'total_semaphores': total_sems,
        'max_arrays': sem_limits.get('semmni', 0),
        'max_total': sem_limits.get('semmns', 0),
        'arrays_pct': (sem_arrays / sem_limits['semmni'] * 100)
            if sem_limits.get('semmni', 0) > 0 else 0,
        'total_pct': (total_sems / sem_limits['semmns'] * 100)
            if sem_limits.get('semmns', 0) > 0 else 0,
    }

    # Shared memory usage
    shm_segments = len(stats.get('shared_memory', []))
    shm_bytes = sum(s.get('bytes', 0) for s in stats.get('shared_memory', []))
    shm_max_segments = limits.get('shmmni', 0)

    usage['shared_memory'] = {
        'segments': shm_segments,
        'total_bytes': shm_bytes,
        'max_segments': shm_max_segments,
        'segments_pct': (shm_segments / shm_max_segments * 100)
            if shm_max_segments > 0 else 0,
    }

    # Message queue usage
    queues = stats.get('message_queues', [])
    queue_count = len(queues)
    queue_bytes = sum(q.get('used_bytes', 0) for q in queues)
    queue_msgs = sum(q.get('messages', 0) for q in queues)
    max_queues = limits.get('msgmni', 0)

    usage['message_queues'] = {
        'queues': queue_count,
        'total_bytes': queue_bytes,
        'total_messages': queue_msgs,
        'max_queues': max_queues,
        'queues_pct': (queue_count / max_queues * 100)
            if max_queues > 0 else 0,
    }

    return usage


def detect_orphans(stats):
    """Detect potentially orphaned IPC resources.

    Args:
        stats: IPC statistics dict

    Returns:
        list: List of potentially orphaned resources
    """
    orphans = []

    # Check for shared memory with 0 attachments (potential orphan)
    for shm in stats.get('shared_memory', []):
        if shm.get('nattch', 0) == 0:
            orphans.append({
                'type': 'shared_memory',
                'id': shm['id'],
                'owner': shm['owner'],
                'bytes': shm['bytes'],
                'reason': 'No processes attached'
            })

    return orphans


def analyze_ipc(stats, usage, warn_pct, crit_pct):
    """Analyze IPC usage and generate issues.

    Args:
        stats: IPC statistics
        usage: Calculated usage statistics
        warn_pct: Warning threshold percentage
        crit_pct: Critical threshold percentage

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Check semaphore array usage
    sem_arrays_pct = usage['semaphores']['arrays_pct']
    if sem_arrays_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'semaphore_arrays',
            'value': usage['semaphores']['arrays'],
            'max': usage['semaphores']['max_arrays'],
            'pct': round(sem_arrays_pct, 1),
            'message': f"Semaphore arrays near limit: {sem_arrays_pct:.1f}% "
                      f"({usage['semaphores']['arrays']}/{usage['semaphores']['max_arrays']})"
        })
    elif sem_arrays_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'semaphore_arrays',
            'value': usage['semaphores']['arrays'],
            'max': usage['semaphores']['max_arrays'],
            'pct': round(sem_arrays_pct, 1),
            'message': f"Semaphore arrays usage high: {sem_arrays_pct:.1f}% "
                      f"({usage['semaphores']['arrays']}/{usage['semaphores']['max_arrays']})"
        })

    # Check total semaphore usage
    sem_total_pct = usage['semaphores']['total_pct']
    if sem_total_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'semaphores_total',
            'value': usage['semaphores']['total_semaphores'],
            'max': usage['semaphores']['max_total'],
            'pct': round(sem_total_pct, 1),
            'message': f"Total semaphores near limit: {sem_total_pct:.1f}%"
        })
    elif sem_total_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'semaphores_total',
            'value': usage['semaphores']['total_semaphores'],
            'max': usage['semaphores']['max_total'],
            'pct': round(sem_total_pct, 1),
            'message': f"Total semaphores usage high: {sem_total_pct:.1f}%"
        })

    # Check shared memory segment usage
    shm_pct = usage['shared_memory']['segments_pct']
    if shm_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'shm_segments',
            'value': usage['shared_memory']['segments'],
            'max': usage['shared_memory']['max_segments'],
            'pct': round(shm_pct, 1),
            'message': f"Shared memory segments near limit: {shm_pct:.1f}%"
        })
    elif shm_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'shm_segments',
            'value': usage['shared_memory']['segments'],
            'max': usage['shared_memory']['max_segments'],
            'pct': round(shm_pct, 1),
            'message': f"Shared memory segments usage high: {shm_pct:.1f}%"
        })

    # Check message queue usage
    queue_pct = usage['message_queues']['queues_pct']
    if queue_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'message_queues',
            'value': usage['message_queues']['queues'],
            'max': usage['message_queues']['max_queues'],
            'pct': round(queue_pct, 1),
            'message': f"Message queues near limit: {queue_pct:.1f}%"
        })
    elif queue_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'message_queues',
            'value': usage['message_queues']['queues'],
            'max': usage['message_queues']['max_queues'],
            'pct': round(queue_pct, 1),
            'message': f"Message queue usage high: {queue_pct:.1f}%"
        })

    # Check for orphaned resources
    orphans = detect_orphans(stats)
    if orphans:
        orphan_bytes = sum(o.get('bytes', 0) for o in orphans)
        issues.append({
            'severity': 'WARNING',
            'resource': 'orphaned_shm',
            'value': len(orphans),
            'bytes': orphan_bytes,
            'message': f"Found {len(orphans)} potentially orphaned shared memory segments "
                      f"({format_bytes(orphan_bytes)} total)"
        })

    return issues


def format_bytes(bytes_val):
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f}PB"


def output_plain(stats, usage, issues, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    print("System V IPC Resource Usage")
    print("=" * 60)

    # Semaphores
    sem = usage['semaphores']
    print(f"\nSemaphores:")
    print(f"  Arrays:     {sem['arrays']:>6} / {sem['max_arrays']:<6} ({sem['arrays_pct']:.1f}%)")
    print(f"  Total sems: {sem['total_semaphores']:>6} / {sem['max_total']:<6} ({sem['total_pct']:.1f}%)")

    # Shared Memory
    shm = usage['shared_memory']
    print(f"\nShared Memory:")
    print(f"  Segments:   {shm['segments']:>6} / {shm['max_segments']:<6} ({shm['segments_pct']:.1f}%)")
    print(f"  Total size: {format_bytes(shm['total_bytes'])}")

    # Message Queues
    mq = usage['message_queues']
    print(f"\nMessage Queues:")
    print(f"  Queues:     {mq['queues']:>6} / {mq['max_queues']:<6} ({mq['queues_pct']:.1f}%)")
    print(f"  Total msgs: {mq['total_messages']}")
    print(f"  Total size: {format_bytes(mq['total_bytes'])}")

    if verbose:
        # Show per-owner breakdown for semaphores
        owners = {}
        for s in stats.get('semaphores', []):
            owner = s['owner']
            if owner not in owners:
                owners[owner] = {'arrays': 0, 'sems': 0}
            owners[owner]['arrays'] += 1
            owners[owner]['sems'] += s.get('nsems', 0)

        if owners:
            print(f"\nSemaphores by owner:")
            for owner, counts in sorted(owners.items(), key=lambda x: -x[1]['sems']):
                print(f"  {owner:<15} {counts['arrays']:>4} arrays, {counts['sems']:>6} semaphores")

        # Show shared memory details
        if stats.get('shared_memory'):
            print(f"\nShared memory segments:")
            for shm in sorted(stats['shared_memory'], key=lambda x: -x['bytes'])[:5]:
                status = "(orphan)" if shm.get('nattch', 0) == 0 else ""
                print(f"  {shm['id']:<10} {shm['owner']:<12} {format_bytes(shm['bytes']):>10} "
                      f"nattch={shm.get('nattch', 0)} {status}")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            print(f"  [{issue['severity']}] {issue['message']}")
    else:
        print(f"\n[OK] IPC resource usage within thresholds")


def output_json(stats, usage, issues):
    """Output results in JSON format."""
    result = {
        'usage': usage,
        'limits': stats.get('limits', {}),
        'issues': issues,
        'resource_counts': {
            'semaphore_arrays': len(stats.get('semaphores', [])),
            'shm_segments': len(stats.get('shared_memory', [])),
            'message_queues': len(stats.get('message_queues', []))
        },
        'has_issues': len(issues) > 0
    }
    print(json.dumps(result, indent=2))


def output_table(stats, usage, issues, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    print(f"{'Resource':<25} {'Used':>10} {'Max':>10} {'Usage':>10}")
    print("-" * 55)

    sem = usage['semaphores']
    print(f"{'Semaphore Arrays':<25} {sem['arrays']:>10} {sem['max_arrays']:>10} {sem['arrays_pct']:>9.1f}%")
    print(f"{'Total Semaphores':<25} {sem['total_semaphores']:>10} {sem['max_total']:>10} {sem['total_pct']:>9.1f}%")

    shm = usage['shared_memory']
    print(f"{'Shared Memory Segments':<25} {shm['segments']:>10} {shm['max_segments']:>10} {shm['segments_pct']:>9.1f}%")

    mq = usage['message_queues']
    print(f"{'Message Queues':<25} {mq['queues']:>10} {mq['max_queues']:>10} {mq['queues_pct']:>9.1f}%")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            print(f"  [{issue['severity']}] {issue['message']}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor System V IPC resource usage (semaphores, shared memory, message queues)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check IPC usage with default thresholds
  %(prog)s --format json        # JSON output for monitoring systems
  %(prog)s --verbose            # Show per-owner breakdown and details
  %(prog)s --warn 60 --crit 80  # Custom thresholds

Thresholds:
  --warn: Usage percentage to trigger warning (default: 75)
  --crit: Usage percentage to trigger critical alert (default: 90)

Common remediation:
  # Increase semaphore limits
  sysctl -w kernel.sem="250 32000 32 128"

  # Increase shared memory limits
  sysctl -w kernel.shmmax=68719476736
  sysctl -w kernel.shmmni=4096

  # Clean up orphaned IPC resources
  ipcrm -m <shmid>   # Remove shared memory
  ipcrm -s <semid>   # Remove semaphore
  ipcrm -q <msqid>   # Remove message queue

Exit codes:
  0 - IPC resource usage is healthy
  1 - High usage or orphaned resources detected
  2 - ipcs unavailable or usage error
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
        help='Show detailed information including per-owner breakdown'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=75.0,
        metavar='PERCENT',
        help='Warning threshold for usage percentage (default: 75)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=90.0,
        metavar='PERCENT',
        help='Critical threshold for usage percentage (default: 90)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit <= args.warn:
        print("Error: --crit must be greater than --warn", file=sys.stderr)
        sys.exit(2)

    # Check if ipcs is available
    try:
        subprocess.run(['ipcs', '-h'], capture_output=True, check=False)
    except FileNotFoundError:
        print("Error: ipcs command not found", file=sys.stderr)
        print("Install util-linux: apt-get install util-linux", file=sys.stderr)
        sys.exit(2)

    # Gather IPC statistics
    stats = get_ipc_stats()

    # Calculate usage percentages
    usage = calculate_usage(stats)

    # Analyze and detect issues
    issues = analyze_ipc(stats, usage, args.warn, args.crit)

    # Output results
    if args.format == 'json':
        output_json(stats, usage, issues)
    elif args.format == 'table':
        output_table(stats, usage, issues, args.warn_only)
    else:  # plain
        output_plain(stats, usage, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == '__main__':
    main()
