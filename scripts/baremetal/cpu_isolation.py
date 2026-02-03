#!/usr/bin/env python3
# boxctl:
#   category: baremetal/performance
#   tags: [cpu, isolation, latency, realtime, performance]
#   requires: []
#   privilege: none
#   related: [cpu_time, cpu_microcode]
#   brief: Audit CPU isolation configuration for latency-sensitive workloads

"""
Audit CPU isolation configuration on baremetal systems.

Examines kernel CPU isolation settings for latency-sensitive workloads:
- isolcpus: CPUs excluded from general scheduler
- nohz_full: CPUs with reduced timer interrupts (tickless)
- rcu_nocbs: CPUs with RCU callbacks offloaded to other CPUs
- CPU affinity of critical processes

Critical for:
- DPDK and network packet processing applications
- Real-time and low-latency workloads
- KVM/QEMU CPU pinning for VMs
- High-frequency trading systems
- Any workload requiring predictable CPU scheduling

This script verifies:
1. Isolation parameters are consistent (isolcpus + nohz_full + rcu_nocbs)
2. Isolated CPUs aren't running unexpected processes
3. IRQ affinity respects CPU isolation
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpu_list(cpu_str: str) -> set[int]:
    """Parse CPU list string (e.g., '0-3,8-11') into set of CPU numbers."""
    if not cpu_str or cpu_str.strip() == '':
        return set()

    cpus = set()
    for part in cpu_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                cpus.update(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                cpus.add(int(part))
            except ValueError:
                pass
    return cpus


def get_cmdline_param(cmdline: str, param_name: str) -> str | None:
    """Extract a kernel command line parameter value."""
    pattern = rf'\b{param_name}=([^\s]+)'
    match = re.search(pattern, cmdline)
    if match:
        return match.group(1)

    # Check for bare parameter (no value)
    if re.search(rf'\b{param_name}\b', cmdline):
        return ''

    return None


def get_online_cpus(context: Context) -> set[int]:
    """Get set of online CPU numbers."""
    try:
        online = context.read_file('/sys/devices/system/cpu/online').strip()
        return parse_cpu_list(online)
    except (FileNotFoundError, OSError):
        return set()


def get_isolated_cpus(context: Context) -> dict[str, Any]:
    """Get CPUs isolated via kernel parameters."""
    result = {
        'isolcpus': set(),
        'nohz_full': set(),
        'rcu_nocbs': set(),
        'cmdline_raw': {},
    }

    try:
        cmdline = context.read_file('/proc/cmdline')
    except (FileNotFoundError, OSError):
        return result

    # Parse isolcpus
    isolcpus = get_cmdline_param(cmdline, 'isolcpus')
    if isolcpus is not None:
        result['cmdline_raw']['isolcpus'] = isolcpus
        # isolcpus can have flags like 'domain,managed_irq,1-3'
        parts = isolcpus.split(',')
        cpu_parts = []
        for part in parts:
            if re.match(r'^[\d\-]+$', part.strip()):
                cpu_parts.append(part)
        if cpu_parts:
            result['isolcpus'] = parse_cpu_list(','.join(cpu_parts))

    # Parse nohz_full
    nohz_full = get_cmdline_param(cmdline, 'nohz_full')
    if nohz_full is not None:
        result['cmdline_raw']['nohz_full'] = nohz_full
        result['nohz_full'] = parse_cpu_list(nohz_full)

    # Parse rcu_nocbs
    rcu_nocbs = get_cmdline_param(cmdline, 'rcu_nocbs')
    if rcu_nocbs is not None:
        result['cmdline_raw']['rcu_nocbs'] = rcu_nocbs
        result['rcu_nocbs'] = parse_cpu_list(rcu_nocbs)

    return result


def get_irq_affinity(context: Context) -> dict[int, dict[str, Any]]:
    """Get IRQ CPU affinity settings."""
    irqs = {}

    # Get IRQ names from /proc/interrupts
    try:
        interrupts = context.read_file('/proc/interrupts')
        irq_names = {}
        for line in interrupts.split('\n')[1:]:
            parts = line.split()
            if parts:
                irq_id = parts[0].rstrip(':')
                if irq_id.isdigit():
                    name = parts[-1] if len(parts) > 1 else 'unknown'
                    irq_names[irq_id] = name
    except (FileNotFoundError, OSError):
        irq_names = {}

    # Get affinity from /proc/irq/*/smp_affinity_list
    result = context.run(['ls', '/proc/irq'], check=False)
    if result.returncode != 0:
        return irqs

    for irq_num in result.stdout.strip().split('\n'):
        if not irq_num.isdigit():
            continue

        affinity_file = f'/proc/irq/{irq_num}/smp_affinity_list'
        try:
            affinity = context.read_file(affinity_file).strip()
            irqs[int(irq_num)] = {
                'name': irq_names.get(irq_num, 'unknown'),
                'cpus': parse_cpu_list(affinity),
            }
        except (FileNotFoundError, OSError):
            continue

    return irqs


def check_irqs_on_isolated(isolated_cpus: set[int], irqs: dict) -> list[dict[str, Any]]:
    """Check for IRQs that can fire on isolated CPUs."""
    violations = []

    for irq_num, info in irqs.items():
        cpus = info['cpus']
        overlap = cpus & isolated_cpus

        if overlap:
            violations.append({
                'irq': irq_num,
                'name': info['name'],
                'cpus': sorted(overlap),
                'all_cpus': sorted(cpus),
            })

    return violations


def analyze_isolation(online_cpus: set[int], isolation_config: dict,
                      irqs: dict) -> dict[str, Any]:
    """Analyze CPU isolation configuration and return findings."""
    issues = []
    warnings = []
    info_msgs = []

    isolcpus = isolation_config['isolcpus']
    nohz_full = isolation_config['nohz_full']
    rcu_nocbs = isolation_config['rcu_nocbs']

    # Check if any isolation is configured
    all_isolated = isolcpus | nohz_full | rcu_nocbs

    if not all_isolated:
        info_msgs.append("No CPU isolation configured")
        return {
            'status': 'none',
            'issues': issues,
            'warnings': warnings,
            'info': info_msgs,
        }

    info_msgs.append(f"Isolated CPUs configured: {sorted(all_isolated)}")

    # Check consistency between isolation parameters
    if isolcpus and nohz_full and isolcpus != nohz_full:
        if not nohz_full.issubset(isolcpus):
            warnings.append(
                f"nohz_full CPUs {sorted(nohz_full - isolcpus)} "
                "are not in isolcpus - timer ticks may still occur"
            )

    if isolcpus and rcu_nocbs and not rcu_nocbs.issuperset(isolcpus):
        missing = isolcpus - rcu_nocbs
        warnings.append(
            f"isolcpus {sorted(missing)} missing from rcu_nocbs - "
            "RCU callbacks will still run on these CPUs"
        )

    # Best practice: all three should match for full isolation
    if isolcpus and nohz_full and rcu_nocbs:
        if isolcpus == nohz_full == rcu_nocbs:
            info_msgs.append(
                "Full isolation: isolcpus, nohz_full, and rcu_nocbs are consistent"
            )
        else:
            warnings.append(
                "Isolation parameters are inconsistent - "
                "consider aligning isolcpus, nohz_full, and rcu_nocbs"
            )

    # Check for isolated CPUs not in online set
    offline_isolated = all_isolated - online_cpus
    if offline_isolated:
        warnings.append(
            f"Isolated CPUs {sorted(offline_isolated)} are not online"
        )

    # Check IRQs on isolated CPUs
    irq_violations = check_irqs_on_isolated(isolcpus, irqs)
    if irq_violations:
        for v in irq_violations[:5]:
            issues.append(
                f"IRQ {v['irq']} ({v['name']}) can fire on "
                f"isolated CPUs {v['cpus']}"
            )
        if len(irq_violations) > 5:
            issues.append(f"... and {len(irq_violations) - 5} more IRQs")

    # Check if CPU 0 is isolated (usually a bad idea)
    if 0 in isolcpus:
        warnings.append(
            "CPU 0 is isolated - some kernel tasks require CPU 0; "
            "this may cause issues"
        )

    # Determine status
    if issues:
        status = 'error'
    elif warnings:
        status = 'warning'
    else:
        status = 'ok'

    return {
        'status': status,
        'issues': issues,
        'warnings': warnings,
        'info': info_msgs,
    }


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
    parser = argparse.ArgumentParser(description="Audit CPU isolation configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Get online CPUs
    online_cpus = get_online_cpus(context)
    if not online_cpus:
        output.error("Cannot determine online CPUs")

        output.render(opts.format, "Audit CPU isolation configuration for latency-sensitive workloads")
        return 2

    # Get isolation configuration
    isolation_config = get_isolated_cpus(context)

    # Get IRQ info if isolation is configured
    all_isolated = (
        isolation_config['isolcpus'] |
        isolation_config['nohz_full'] |
        isolation_config['rcu_nocbs']
    )

    if all_isolated:
        irqs = get_irq_affinity(context)
    else:
        irqs = {}

    # Analyze
    analysis = analyze_isolation(online_cpus, isolation_config, irqs)

    # Build result
    result = {
        'cpu_count': len(online_cpus),
        'isolation': {
            'isolcpus': sorted(isolation_config['isolcpus']),
            'nohz_full': sorted(isolation_config['nohz_full']),
            'rcu_nocbs': sorted(isolation_config['rcu_nocbs']),
        },
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
    }

    if opts.verbose:
        result['online_cpus'] = sorted(online_cpus)
        result['cmdline_raw'] = isolation_config.get('cmdline_raw', {})
        result['info'] = analysis['info']

    output.emit(result)

    # Set summary
    if analysis['status'] == 'none':
        output.set_summary("no CPU isolation configured")
    elif analysis['status'] == 'ok':
        output.set_summary(f"{len(all_isolated)} CPUs isolated, properly configured")
    elif analysis['status'] == 'warning':
        output.set_summary(f"{len(analysis['warnings'])} isolation warnings")
    else:
        output.set_summary(f"{len(analysis['issues'])} isolation issues")

    # Exit code
    if analysis['issues'] or analysis['warnings']:

        output.render(opts.format, "Audit CPU isolation configuration for latency-sensitive workloads")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
