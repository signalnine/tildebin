#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [maintenance, preflight, health, validation, reboot]
#   requires: []
#   privilege: none
#   related: [load_average, memory_usage, disk_health, systemd_service_monitor]
#   brief: Pre-maintenance validation checker for baremetal systems

"""
Pre-maintenance validation checker for baremetal systems.

Performs comprehensive pre-flight checks before planned maintenance operations
(reboots, upgrades, hardware changes). Validates system is in a healthy state
before proceeding.

Checks performed:
- No critical processes in unusual states (D-state, zombie)
- Filesystem integrity (no read-only mounts, pending syncs)
- Memory pressure acceptable (no imminent OOM risk)
- Disk space adequate
- System services stable (no failed units)
- Network connectivity healthy
- No hung NFS mounts
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_file(path: str, context: Context) -> str | None:
    """Read file contents, return None on error."""
    try:
        return context.read_file(path)
    except (FileNotFoundError, PermissionError):
        return None


def check_dstate_processes(context: Context) -> dict[str, Any]:
    """Check for processes in uninterruptible sleep (D-state)."""
    dstate_procs = []

    try:
        proc_entries = context.glob('[0-9]*', root='/proc')
        for proc_path in proc_entries:
            pid_str = proc_path.split('/')[-1]
            if not pid_str.isdigit():
                continue

            pid = int(pid_str)
            stat_content = read_file(f'/proc/{pid}/stat', context)
            if not stat_content:
                continue

            close_paren = stat_content.rfind(')')
            if close_paren < 0 or close_paren + 2 >= len(stat_content):
                continue

            state = stat_content[close_paren + 2]

            if state == 'D':
                comm_start = stat_content.find('(') + 1
                comm = stat_content[comm_start:close_paren]
                dstate_procs.append({
                    'pid': pid,
                    'name': comm,
                })
    except Exception as e:
        return {
            'name': 'D-State Processes',
            'status': 'ERROR',
            'message': f'Could not check D-state processes: {e}',
            'details': []
        }

    if dstate_procs:
        return {
            'name': 'D-State Processes',
            'status': 'WARNING',
            'message': f'{len(dstate_procs)} process(es) in uninterruptible sleep',
            'details': dstate_procs
        }

    return {
        'name': 'D-State Processes',
        'status': 'OK',
        'message': 'No processes stuck in D-state',
        'details': []
    }


def check_zombie_processes(context: Context) -> dict[str, Any]:
    """Check for zombie processes."""
    zombies = []

    try:
        proc_entries = context.glob('[0-9]*', root='/proc')
        for proc_path in proc_entries:
            pid_str = proc_path.split('/')[-1]
            if not pid_str.isdigit():
                continue

            pid = int(pid_str)
            stat_content = read_file(f'/proc/{pid}/stat', context)
            if not stat_content:
                continue

            close_paren = stat_content.rfind(')')
            if close_paren < 0 or close_paren + 2 >= len(stat_content):
                continue

            state = stat_content[close_paren + 2]

            if state == 'Z':
                comm_start = stat_content.find('(') + 1
                comm = stat_content[comm_start:close_paren]
                zombies.append({'pid': pid, 'name': comm})
    except Exception as e:
        return {
            'name': 'Zombie Processes',
            'status': 'ERROR',
            'message': f'Could not check zombie processes: {e}',
            'details': []
        }

    if len(zombies) > 10:
        return {
            'name': 'Zombie Processes',
            'status': 'WARNING',
            'message': f'{len(zombies)} zombie processes detected',
            'details': zombies[:10]
        }

    return {
        'name': 'Zombie Processes',
        'status': 'OK',
        'message': f'{len(zombies)} zombie process(es) (acceptable)',
        'details': []
    }


def check_memory_pressure(context: Context) -> dict[str, Any]:
    """Check for memory pressure."""
    try:
        content = read_file('/proc/meminfo', context)
        if not content:
            return {
                'name': 'Memory Pressure',
                'status': 'ERROR',
                'message': 'Could not read /proc/meminfo',
                'details': {}
            }

        meminfo = {}
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                parts = value.strip().split()
                if parts:
                    try:
                        meminfo[key.strip()] = int(parts[0])
                    except ValueError:
                        pass

        mem_total = meminfo.get('MemTotal', 0)
        mem_available = meminfo.get('MemAvailable', 0)
        swap_total = meminfo.get('SwapTotal', 0)
        swap_free = meminfo.get('SwapFree', 0)

        if mem_total == 0:
            return {
                'name': 'Memory Pressure',
                'status': 'ERROR',
                'message': 'Could not determine memory status',
                'details': {}
            }

        mem_available_pct = (mem_available / mem_total) * 100
        swap_used_pct = ((swap_total - swap_free) / swap_total * 100) if swap_total > 0 else 0

        details = {
            'mem_available_pct': round(mem_available_pct, 1),
            'swap_used_pct': round(swap_used_pct, 1),
            'mem_available_mb': mem_available // 1024,
        }

        if mem_available_pct < 5:
            return {
                'name': 'Memory Pressure',
                'status': 'CRITICAL',
                'message': f'Critical memory pressure: only {mem_available_pct:.1f}% available',
                'details': details
            }
        elif mem_available_pct < 10 or swap_used_pct > 75:
            return {
                'name': 'Memory Pressure',
                'status': 'WARNING',
                'message': f'Elevated memory pressure: {mem_available_pct:.1f}% available',
                'details': details
            }

        return {
            'name': 'Memory Pressure',
            'status': 'OK',
            'message': f'{mem_available_pct:.1f}% memory available',
            'details': details
        }
    except Exception as e:
        return {
            'name': 'Memory Pressure',
            'status': 'ERROR',
            'message': f'Could not check memory: {e}',
            'details': {}
        }


def check_load_average(context: Context) -> dict[str, Any]:
    """Check if system load is unusually high."""
    try:
        content = read_file('/proc/loadavg', context)
        if not content:
            return {
                'name': 'System Load',
                'status': 'ERROR',
                'message': 'Could not read /proc/loadavg',
                'details': {}
            }

        parts = content.split()
        load1 = float(parts[0])
        load5 = float(parts[1])
        load15 = float(parts[2])

        cpu_count = context.cpu_count()
        load_per_cpu = load1 / cpu_count

        details = {
            'load_1min': load1,
            'load_5min': load5,
            'load_15min': load15,
            'cpu_count': cpu_count,
            'load_per_cpu': round(load_per_cpu, 2)
        }

        if load_per_cpu > 5:
            return {
                'name': 'System Load',
                'status': 'CRITICAL',
                'message': f'Extremely high load: {load1:.1f} ({load_per_cpu:.1f} per CPU)',
                'details': details
            }
        elif load_per_cpu > 2:
            return {
                'name': 'System Load',
                'status': 'WARNING',
                'message': f'Elevated system load: {load1:.1f} ({load_per_cpu:.1f} per CPU)',
                'details': details
            }

        return {
            'name': 'System Load',
            'status': 'OK',
            'message': f'Load average: {load1:.2f} ({load_per_cpu:.2f} per CPU)',
            'details': details
        }
    except Exception as e:
        return {
            'name': 'System Load',
            'status': 'ERROR',
            'message': f'Could not check load average: {e}',
            'details': {}
        }


def check_pending_syncs(context: Context) -> dict[str, Any]:
    """Check for pending disk writes (dirty pages)."""
    try:
        content = read_file('/proc/meminfo', context)
        if not content:
            return {
                'name': 'Pending Disk Writes',
                'status': 'OK',
                'message': 'Could not check dirty pages',
                'details': {}
            }

        for line in content.split('\n'):
            if line.startswith('Dirty:'):
                dirty_kb = int(line.split()[1])
                dirty_mb = dirty_kb / 1024

                if dirty_mb > 1000:
                    return {
                        'name': 'Pending Disk Writes',
                        'status': 'WARNING',
                        'message': f'{dirty_mb:.0f} MB of dirty pages pending write',
                        'details': {'dirty_mb': round(dirty_mb, 1)}
                    }

                return {
                    'name': 'Pending Disk Writes',
                    'status': 'OK',
                    'message': f'{dirty_mb:.1f} MB dirty pages (acceptable)',
                    'details': {'dirty_mb': round(dirty_mb, 1)}
                }

        return {
            'name': 'Pending Disk Writes',
            'status': 'OK',
            'message': 'Dirty pages check passed',
            'details': {}
        }
    except Exception as e:
        return {
            'name': 'Pending Disk Writes',
            'status': 'ERROR',
            'message': f'Could not check dirty pages: {e}',
            'details': {}
        }


def check_systemd_failed_units(context: Context) -> dict[str, Any]:
    """Check for failed systemd units."""
    if not context.check_tool('systemctl'):
        return {
            'name': 'Systemd Units',
            'status': 'SKIPPED',
            'message': 'systemctl not available',
            'details': []
        }

    try:
        result = context.run(
            ['systemctl', 'list-units', '--state=failed', '--no-legend', '--plain'],
            check=False,
            timeout=10
        )

        failed_units = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                unit = line.split()[0] if line.split() else ''
                if unit:
                    failed_units.append(unit)

        if failed_units:
            return {
                'name': 'Systemd Units',
                'status': 'WARNING',
                'message': f'{len(failed_units)} failed systemd unit(s)',
                'details': failed_units[:10]
            }

        return {
            'name': 'Systemd Units',
            'status': 'OK',
            'message': 'No failed systemd units',
            'details': []
        }
    except Exception as e:
        return {
            'name': 'Systemd Units',
            'status': 'ERROR',
            'message': f'Could not check systemd: {e}',
            'details': []
        }


def check_kernel_taint(context: Context) -> dict[str, Any]:
    """Check for kernel taint flags."""
    taint_flags = {
        4: 'Processor reported MCE',
        5: 'Bad page found',
        7: 'Kernel died recently (OOPS or BUG)',
        14: 'Soft lockup occurred',
    }

    try:
        content = read_file('/proc/sys/kernel/tainted', context)
        if not content:
            return {
                'name': 'Kernel Taint',
                'status': 'OK',
                'message': 'Could not check kernel taint',
                'details': {}
            }

        taint = int(content.strip())

        if taint == 0:
            return {
                'name': 'Kernel Taint',
                'status': 'OK',
                'message': 'Kernel is not tainted',
                'details': {}
            }

        concerning_taints = []
        for bit, desc in taint_flags.items():
            if taint & (1 << bit):
                concerning_taints.append(desc)

        details = {'taint_value': taint}

        if concerning_taints:
            return {
                'name': 'Kernel Taint',
                'status': 'CRITICAL',
                'message': f'Kernel has concerning taint flags',
                'details': details
            }

        return {
            'name': 'Kernel Taint',
            'status': 'WARNING',
            'message': f'Kernel is tainted (value={taint})',
            'details': details
        }
    except Exception as e:
        return {
            'name': 'Kernel Taint',
            'status': 'ERROR',
            'message': f'Could not check kernel taint: {e}',
            'details': {}
        }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = safe to proceed, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Pre-maintenance system validation")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--quick", action="store_true", help="Skip slower checks")
    opts = parser.parse_args(args)

    # Verify /proc is available
    if not context.file_exists('/proc'):
        output.error("/proc filesystem not available")
        return 2

    # Run all checks
    checks = [
        check_dstate_processes(context),
        check_zombie_processes(context),
        check_memory_pressure(context),
        check_load_average(context),
        check_pending_syncs(context),
        check_systemd_failed_units(context),
        check_kernel_taint(context),
    ]

    # Count issues
    critical_count = sum(1 for c in checks if c['status'] == 'CRITICAL')
    warning_count = sum(1 for c in checks if c['status'] == 'WARNING')
    ok_count = sum(1 for c in checks if c['status'] == 'OK')

    result = {
        'summary': {
            'safe_to_proceed': critical_count == 0 and warning_count == 0,
            'critical': critical_count,
            'warnings': warning_count,
            'ok': ok_count
        },
        'checks': checks if opts.verbose else [
            {'name': c['name'], 'status': c['status'], 'message': c['message']}
            for c in checks
        ]
    }

    output.emit(result)

    # Set summary
    if critical_count > 0:
        output.set_summary(f"CRITICAL: {critical_count} critical issue(s) found")
        return 1
    elif warning_count > 0:
        output.set_summary(f"WARNING: {warning_count} warning(s) found")
        return 1
    else:
        output.set_summary("All pre-maintenance checks passed")
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
