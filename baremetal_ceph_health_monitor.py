#!/usr/bin/env python3
"""
Monitor Ceph cluster health for baremetal storage infrastructure.

This script checks the health of a Ceph distributed storage cluster by
querying the cluster status, OSD health, pool utilization, and monitoring
for degraded or recovering placement groups. Essential for large-scale
baremetal environments using Ceph for object, block, or file storage.

Key features:
- Overall cluster health status (HEALTH_OK, HEALTH_WARN, HEALTH_ERR)
- OSD status and capacity monitoring
- Pool utilization and PG state analysis
- Monitor quorum verification
- MDS (Metadata Server) health for CephFS
- Detection of slow or blocked requests

Exit codes:
    0 - Cluster healthy (HEALTH_OK)
    1 - Warnings or errors detected (HEALTH_WARN or HEALTH_ERR)
    2 - Usage error or ceph command not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


def run_ceph_command(cmd_args):
    """Execute a ceph command and return parsed JSON output."""
    try:
        cmd = ['ceph'] + cmd_args + ['--format', 'json']
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return None, result.stderr
        return json.loads(result.stdout), None
    except FileNotFoundError:
        return None, "ceph command not found"
    except json.JSONDecodeError as e:
        return None, f"Failed to parse JSON: {e}"
    except subprocess.TimeoutExpired:
        return None, "Command timed out"
    except Exception as e:
        return None, str(e)


def check_ceph_available():
    """Check if ceph command is available."""
    try:
        result = subprocess.run(
            ['which', 'ceph'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_cluster_status():
    """Get overall cluster status."""
    data, error = run_ceph_command(['status'])
    if error:
        return None, error
    return data, None


def get_osd_tree():
    """Get OSD tree structure."""
    data, error = run_ceph_command(['osd', 'tree'])
    if error:
        return None, error
    return data, None


def get_osd_df():
    """Get OSD disk usage."""
    data, error = run_ceph_command(['osd', 'df'])
    if error:
        return None, error
    return data, None


def get_pool_stats():
    """Get pool statistics."""
    data, error = run_ceph_command(['df', 'detail'])
    if error:
        return None, error
    return data, None


def get_health_detail():
    """Get detailed health information."""
    data, error = run_ceph_command(['health', 'detail'])
    if error:
        return None, error
    return data, None


def analyze_cluster_health(status):
    """Analyze cluster health from status output."""
    health_info = {
        'status': 'unknown',
        'checks': [],
        'messages': []
    }

    if not status:
        return health_info

    health = status.get('health', {})
    health_info['status'] = health.get('status', 'unknown')

    # Extract health checks
    checks = health.get('checks', {})
    for check_name, check_data in checks.items():
        severity = check_data.get('severity', 'unknown')
        summary = check_data.get('summary', {}).get('message', '')
        health_info['checks'].append({
            'name': check_name,
            'severity': severity,
            'message': summary
        })

    return health_info


def analyze_osd_health(osd_tree, osd_df):
    """Analyze OSD health and capacity."""
    osd_info = {
        'total': 0,
        'up': 0,
        'down': 0,
        'in': 0,
        'out': 0,
        'osds': [],
        'warnings': []
    }

    if not osd_tree:
        return osd_info

    # Process OSD tree nodes
    nodes = osd_tree.get('nodes', [])
    for node in nodes:
        if node.get('type') == 'osd':
            osd_id = node.get('id', -1)
            is_up = node.get('status', '') == 'up'
            is_in = node.get('reweight', 0) > 0

            osd_info['total'] += 1
            if is_up:
                osd_info['up'] += 1
            else:
                osd_info['down'] += 1
            if is_in:
                osd_info['in'] += 1
            else:
                osd_info['out'] += 1

            osd_entry = {
                'id': osd_id,
                'name': node.get('name', f'osd.{osd_id}'),
                'status': 'up' if is_up else 'down',
                'in_cluster': is_in,
                'crush_weight': node.get('crush_weight', 0),
                'reweight': node.get('reweight', 0)
            }

            # Add capacity info from osd_df if available
            if osd_df:
                osd_nodes = osd_df.get('nodes', [])
                for df_node in osd_nodes:
                    if df_node.get('id') == osd_id:
                        osd_entry['utilization'] = df_node.get('utilization', 0)
                        osd_entry['kb_used'] = df_node.get('kb_used', 0)
                        osd_entry['kb_avail'] = df_node.get('kb_avail', 0)
                        osd_entry['pgs'] = df_node.get('pgs', 0)
                        break

            osd_info['osds'].append(osd_entry)

            # Check for issues
            if not is_up:
                osd_info['warnings'].append(f"OSD {osd_id} is DOWN")
            if not is_in and is_up:
                osd_info['warnings'].append(f"OSD {osd_id} is UP but OUT")
            if osd_entry.get('utilization', 0) > 85:
                osd_info['warnings'].append(
                    f"OSD {osd_id} utilization is high: "
                    f"{osd_entry['utilization']:.1f}%"
                )

    return osd_info


def analyze_pool_health(pool_stats):
    """Analyze pool utilization and health."""
    pool_info = {
        'pools': [],
        'total_capacity': 0,
        'used_capacity': 0,
        'warnings': []
    }

    if not pool_stats:
        return pool_info

    stats = pool_stats.get('stats', {})
    pool_info['total_capacity'] = stats.get('total_bytes', 0)
    pool_info['used_capacity'] = stats.get('total_used_bytes', 0)

    pools = pool_stats.get('pools', [])
    for pool in pools:
        pool_name = pool.get('name', 'unknown')
        pool_stats_data = pool.get('stats', {})

        pool_entry = {
            'name': pool_name,
            'id': pool.get('id', -1),
            'stored': pool_stats_data.get('stored', 0),
            'objects': pool_stats_data.get('objects', 0),
            'percent_used': pool_stats_data.get('percent_used', 0) * 100
        }

        pool_info['pools'].append(pool_entry)

        # Check for high utilization
        if pool_entry['percent_used'] > 80:
            pool_info['warnings'].append(
                f"Pool '{pool_name}' utilization is high: "
                f"{pool_entry['percent_used']:.1f}%"
            )

    return pool_info


def analyze_pg_status(status):
    """Analyze placement group status from cluster status."""
    pg_info = {
        'total': 0,
        'active_clean': 0,
        'degraded': 0,
        'recovering': 0,
        'undersized': 0,
        'stale': 0,
        'other_states': {},
        'warnings': []
    }

    if not status:
        return pg_info

    pgmap = status.get('pgmap', {})
    pg_info['total'] = pgmap.get('num_pgs', 0)

    pgs_by_state = pgmap.get('pgs_by_state', [])
    for state_entry in pgs_by_state:
        state_name = state_entry.get('state_name', '')
        count = state_entry.get('count', 0)

        if state_name == 'active+clean':
            pg_info['active_clean'] = count
        elif 'degraded' in state_name:
            pg_info['degraded'] += count
        elif 'recovering' in state_name or 'backfilling' in state_name:
            pg_info['recovering'] += count
        elif 'undersized' in state_name:
            pg_info['undersized'] += count
        elif 'stale' in state_name:
            pg_info['stale'] += count
        else:
            pg_info['other_states'][state_name] = count

    # Add warnings for concerning PG states
    if pg_info['degraded'] > 0:
        pg_info['warnings'].append(
            f"{pg_info['degraded']} PGs are degraded"
        )
    if pg_info['stale'] > 0:
        pg_info['warnings'].append(
            f"{pg_info['stale']} PGs are stale"
        )
    if pg_info['undersized'] > 0:
        pg_info['warnings'].append(
            f"{pg_info['undersized']} PGs are undersized"
        )

    return pg_info


def analyze_monitor_status(status):
    """Analyze monitor quorum status."""
    mon_info = {
        'total': 0,
        'in_quorum': 0,
        'quorum_names': [],
        'warnings': []
    }

    if not status:
        return mon_info

    monmap = status.get('monmap', {})
    mon_info['total'] = monmap.get('num_mons', 0)

    quorum = status.get('quorum', [])
    quorum_names = status.get('quorum_names', [])
    mon_info['in_quorum'] = len(quorum)
    mon_info['quorum_names'] = quorum_names

    if mon_info['in_quorum'] < mon_info['total']:
        out_of_quorum = mon_info['total'] - mon_info['in_quorum']
        mon_info['warnings'].append(
            f"{out_of_quorum} monitors out of quorum"
        )

    return mon_info


def format_bytes(size_bytes):
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} EB"


def output_plain(results, verbose=False, warn_only=False):
    """Output results in plain text format."""
    health = results['health']
    osds = results['osds']
    pools = results['pools']
    pgs = results['pgs']
    monitors = results['monitors']

    # Overall health status
    status_symbol = {
        'HEALTH_OK': '[OK]',
        'HEALTH_WARN': '[WARN]',
        'HEALTH_ERR': '[ERR]'
    }.get(health['status'], '[???]')

    print(f"{status_symbol} Ceph Cluster Health: {health['status']}")
    print()

    # Health checks
    if health['checks']:
        print("Health Checks:")
        for check in health['checks']:
            severity = check['severity'].upper()
            print(f"  [{severity}] {check['name']}: {check['message']}")
        print()

    # Monitor status
    if monitors['warnings'] or not warn_only:
        print(f"Monitors: {monitors['in_quorum']}/{monitors['total']} in quorum")
        if monitors['quorum_names'] and verbose:
            print(f"  Quorum: {', '.join(monitors['quorum_names'])}")
        for warning in monitors['warnings']:
            print(f"  [WARN] {warning}")
        print()

    # OSD status
    if osds['warnings'] or not warn_only:
        print(f"OSDs: {osds['up']}/{osds['total']} up, "
              f"{osds['in']}/{osds['total']} in")
        for warning in osds['warnings']:
            print(f"  [WARN] {warning}")

        if verbose and osds['osds']:
            print("  OSD Details:")
            for osd in sorted(osds['osds'], key=lambda x: x['id']):
                status = osd['status'].upper()
                util = osd.get('utilization', 0)
                print(f"    osd.{osd['id']}: {status} "
                      f"(util: {util:.1f}%, pgs: {osd.get('pgs', 0)})")
        print()

    # PG status
    if pgs['warnings'] or not warn_only:
        print(f"Placement Groups: {pgs['total']} total, "
              f"{pgs['active_clean']} active+clean")
        if pgs['degraded'] > 0:
            print(f"  Degraded: {pgs['degraded']}")
        if pgs['recovering'] > 0:
            print(f"  Recovering: {pgs['recovering']}")
        for warning in pgs['warnings']:
            print(f"  [WARN] {warning}")
        print()

    # Pool status
    if pools['pools'] or not warn_only:
        total_cap = format_bytes(pools['total_capacity'])
        used_cap = format_bytes(pools['used_capacity'])
        print(f"Storage: {used_cap} / {total_cap} used")

        if verbose:
            print("  Pools:")
            for pool in pools['pools']:
                stored = format_bytes(pool['stored'])
                print(f"    {pool['name']}: {stored} "
                      f"({pool['percent_used']:.1f}% used, "
                      f"{pool['objects']} objects)")

        for warning in pools['warnings']:
            print(f"  [WARN] {warning}")
        print()


def output_json(results):
    """Output results in JSON format."""
    output = {
        'timestamp': datetime.now().isoformat(),
        'health': results['health'],
        'monitors': results['monitors'],
        'osds': {
            'total': results['osds']['total'],
            'up': results['osds']['up'],
            'down': results['osds']['down'],
            'in': results['osds']['in'],
            'out': results['osds']['out'],
            'warnings': results['osds']['warnings'],
            'details': results['osds']['osds']
        },
        'pgs': results['pgs'],
        'pools': results['pools'],
        'summary': {
            'is_healthy': results['health']['status'] == 'HEALTH_OK',
            'total_warnings': (
                len(results['health']['checks']) +
                len(results['osds']['warnings']) +
                len(results['pools']['warnings']) +
                len(results['pgs']['warnings']) +
                len(results['monitors']['warnings'])
            )
        }
    }
    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format."""
    health = results['health']
    osds = results['osds']

    # Summary table
    print(f"{'Component':<15} {'Status':<15} {'Details':<40}")
    print("-" * 70)

    # Health
    print(f"{'Cluster':<15} {health['status']:<15} "
          f"{len(health['checks'])} checks")

    # Monitors
    mon = results['monitors']
    mon_status = 'OK' if not mon['warnings'] else 'WARN'
    print(f"{'Monitors':<15} {mon_status:<15} "
          f"{mon['in_quorum']}/{mon['total']} in quorum")

    # OSDs
    osd_status = 'OK' if not osds['warnings'] else 'WARN'
    print(f"{'OSDs':<15} {osd_status:<15} "
          f"{osds['up']}/{osds['total']} up, {osds['in']}/{osds['total']} in")

    # PGs
    pgs = results['pgs']
    pg_status = 'OK' if not pgs['warnings'] else 'WARN'
    print(f"{'PGs':<15} {pg_status:<15} "
          f"{pgs['active_clean']}/{pgs['total']} active+clean")

    # Pools
    pools = results['pools']
    pool_status = 'OK' if not pools['warnings'] else 'WARN'
    used_pct = 0
    if pools['total_capacity'] > 0:
        used_pct = (pools['used_capacity'] / pools['total_capacity']) * 100
    print(f"{'Storage':<15} {pool_status:<15} "
          f"{used_pct:.1f}% used across {len(pools['pools'])} pools")

    print()

    # Warnings section
    all_warnings = (
        [(c['name'], c['message']) for c in health['checks']] +
        [('OSD', w) for w in osds['warnings']] +
        [('Pool', w) for w in pools['warnings']] +
        [('PG', w) for w in pgs['warnings']] +
        [('Monitor', w) for w in mon['warnings']]
    )

    if all_warnings:
        print("Warnings:")
        print(f"{'Source':<15} {'Message':<55}")
        print("-" * 70)
        for source, message in all_warnings:
            print(f"{source:<15} {message[:55]}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Ceph cluster health including OSD status, '
                    'pool utilization, and placement group (PG) states',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Basic health check
  %(prog)s --format json           # JSON output for monitoring systems
  %(prog)s --format table          # Tabular summary
  %(prog)s -v                      # Verbose output with OSD details
  %(prog)s -w                      # Only show warnings

Exit codes:
  0 - Cluster is healthy (HEALTH_OK)
  1 - Warnings or errors detected
  2 - Usage error or ceph not available
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
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    args = parser.parse_args()

    # Check if ceph command is available
    if not check_ceph_available():
        print("Error: ceph command not found in PATH", file=sys.stderr)
        print("Install ceph-common package or ensure ceph is in PATH",
              file=sys.stderr)
        sys.exit(2)

    # Gather cluster information
    status, error = get_cluster_status()
    if error:
        if args.format == 'json':
            print(json.dumps({'error': error, 'health': {'status': 'unknown'}}))
        else:
            print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    osd_tree, _ = get_osd_tree()
    osd_df, _ = get_osd_df()
    pool_stats, _ = get_pool_stats()

    # Analyze data
    results = {
        'health': analyze_cluster_health(status),
        'osds': analyze_osd_health(osd_tree, osd_df),
        'pools': analyze_pool_health(pool_stats),
        'pgs': analyze_pg_status(status),
        'monitors': analyze_monitor_status(status)
    }

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    is_healthy = results['health']['status'] == 'HEALTH_OK'
    sys.exit(0 if is_healthy else 1)


if __name__ == '__main__':
    main()
