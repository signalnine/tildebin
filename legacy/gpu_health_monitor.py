#!/usr/bin/env python3
"""
Monitor GPU health and performance on baremetal systems.

Checks NVIDIA GPU health metrics including temperature, memory usage, ECC errors,
power consumption, and utilization using nvidia-smi. Essential for monitoring
GPU clusters in ML/AI workloads and detecting hardware issues before failures.

Exit codes:
    0 - Success (all GPUs healthy)
    1 - Warning/Critical issues detected (high temp, ECC errors, etc.)
    2 - Usage error or missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys


def check_nvidia_smi_available():
    """Check if nvidia-smi command is available."""
    try:
        subprocess.run(
            ['nvidia-smi', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_gpu_data():
    """
    Query nvidia-smi for GPU metrics.

    Returns list of GPU dictionaries with health metrics.
    """
    gpus = []

    # Query format for detailed GPU information
    query_fields = [
        'index',
        'name',
        'uuid',
        'temperature.gpu',
        'temperature.memory',
        'utilization.gpu',
        'utilization.memory',
        'memory.total',
        'memory.used',
        'memory.free',
        'power.draw',
        'power.limit',
        'clocks.current.graphics',
        'clocks.current.memory',
        'clocks.max.graphics',
        'clocks.max.memory',
        'ecc.errors.corrected.volatile.total',
        'ecc.errors.uncorrected.volatile.total',
        'pstate',
        'fan.speed',
        'compute_mode'
    ]

    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=' + ','.join(query_fields), '--format=csv,noheader,nounits'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )

        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            values = [v.strip() for v in line.split(', ')]

            if len(values) < len(query_fields):
                continue

            # Parse values, handling [Not Supported] and [N/A]
            def parse_int(val):
                if val in ['[Not Supported]', '[N/A]', 'N/A', '']:
                    return None
                try:
                    return int(float(val))
                except (ValueError, TypeError):
                    return None

            def parse_float(val):
                if val in ['[Not Supported]', '[N/A]', 'N/A', '']:
                    return None
                try:
                    return float(val)
                except (ValueError, TypeError):
                    return None

            gpu = {
                'index': parse_int(values[0]),
                'name': values[1] if values[1] not in ['[Not Supported]', '[N/A]'] else 'Unknown',
                'uuid': values[2] if values[2] not in ['[Not Supported]', '[N/A]'] else None,
                'temperature': {
                    'gpu': parse_int(values[3]),
                    'memory': parse_int(values[4])
                },
                'utilization': {
                    'gpu': parse_int(values[5]),
                    'memory': parse_int(values[6])
                },
                'memory': {
                    'total': parse_int(values[7]),
                    'used': parse_int(values[8]),
                    'free': parse_int(values[9])
                },
                'power': {
                    'draw': parse_float(values[10]),
                    'limit': parse_float(values[11])
                },
                'clocks': {
                    'graphics': parse_int(values[12]),
                    'memory': parse_int(values[13]),
                    'max_graphics': parse_int(values[14]),
                    'max_memory': parse_int(values[15])
                },
                'ecc_errors': {
                    'corrected': parse_int(values[16]),
                    'uncorrected': parse_int(values[17])
                },
                'pstate': values[18] if values[18] not in ['[Not Supported]', '[N/A]'] else None,
                'fan_speed': parse_int(values[19]),
                'compute_mode': values[20] if values[20] not in ['[Not Supported]', '[N/A]'] else None
            }

            # Determine health status
            gpu['status'] = determine_gpu_status(gpu)
            gpus.append(gpu)

    except subprocess.CalledProcessError as e:
        print(f"Error running nvidia-smi: {e}", file=sys.stderr)
        return []

    return gpus


def determine_gpu_status(gpu):
    """
    Determine GPU health status based on metrics.

    Returns 'OK', 'WARNING', or 'CRITICAL'.
    """
    issues = []

    # Temperature checks
    temp = gpu['temperature'].get('gpu')
    if temp is not None:
        if temp >= 90:
            return 'CRITICAL'
        elif temp >= 80:
            issues.append('high_temp')

    # ECC error checks
    ecc_corrected = gpu['ecc_errors'].get('corrected')
    ecc_uncorrected = gpu['ecc_errors'].get('uncorrected')

    if ecc_uncorrected is not None and ecc_uncorrected > 0:
        return 'CRITICAL'

    if ecc_corrected is not None and ecc_corrected > 100:
        issues.append('high_ecc')

    # Memory usage check (>95% is warning)
    mem_total = gpu['memory'].get('total')
    mem_used = gpu['memory'].get('used')
    if mem_total and mem_used:
        usage_pct = (mem_used / mem_total) * 100
        if usage_pct >= 95:
            issues.append('high_memory')

    # Power check (>95% of limit)
    power_draw = gpu['power'].get('draw')
    power_limit = gpu['power'].get('limit')
    if power_draw and power_limit and power_limit > 0:
        power_pct = (power_draw / power_limit) * 100
        if power_pct >= 95:
            issues.append('high_power')

    # Fan speed check (0 RPM when GPU is hot is bad)
    fan_speed = gpu.get('fan_speed')
    if fan_speed == 0 and temp and temp > 50:
        issues.append('fan_stopped')

    if issues:
        return 'WARNING'

    return 'OK'


def format_plain(gpus, warn_only=False, verbose=False):
    """Format GPU data as plain text."""
    output = []

    if warn_only:
        gpus = [g for g in gpus if g['status'] != 'OK']

    if not gpus:
        if warn_only:
            output.append("No GPU warnings or critical conditions detected.")
        else:
            output.append("No GPUs found.")
        return '\n'.join(output)

    for gpu in gpus:
        idx = gpu['index']
        name = gpu['name']
        status = gpu['status']

        # Basic info line
        status_str = f" [{status}]" if status != 'OK' else ""
        output.append(f"GPU {idx}: {name}{status_str}")

        # Temperature
        temp = gpu['temperature'].get('gpu')
        if temp is not None:
            temp_str = f"  Temperature:      {temp}°C"
            if temp >= 80:
                temp_str += " (HIGH)"
            output.append(temp_str)

        # Memory
        mem_used = gpu['memory'].get('used')
        mem_total = gpu['memory'].get('total')
        if mem_used is not None and mem_total is not None:
            usage_pct = (mem_used / mem_total) * 100 if mem_total > 0 else 0
            output.append(f"  Memory:           {mem_used}/{mem_total} MiB ({usage_pct:.1f}%)")

        # Utilization
        util_gpu = gpu['utilization'].get('gpu')
        util_mem = gpu['utilization'].get('memory')
        if util_gpu is not None:
            output.append(f"  GPU Utilization:  {util_gpu}%")

        if verbose:
            # Power
            power_draw = gpu['power'].get('draw')
            power_limit = gpu['power'].get('limit')
            if power_draw is not None and power_limit is not None:
                output.append(f"  Power:            {power_draw:.1f}W / {power_limit:.1f}W")

            # Clocks
            clk_gfx = gpu['clocks'].get('graphics')
            clk_mem = gpu['clocks'].get('memory')
            if clk_gfx is not None:
                output.append(f"  Graphics Clock:   {clk_gfx} MHz")
            if clk_mem is not None:
                output.append(f"  Memory Clock:     {clk_mem} MHz")

            # ECC errors
            ecc_corrected = gpu['ecc_errors'].get('corrected')
            ecc_uncorrected = gpu['ecc_errors'].get('uncorrected')
            if ecc_corrected is not None or ecc_uncorrected is not None:
                corr = ecc_corrected if ecc_corrected is not None else 'N/A'
                uncorr = ecc_uncorrected if ecc_uncorrected is not None else 'N/A'
                ecc_str = f"  ECC Errors:       {corr} corrected, {uncorr} uncorrected"
                if (ecc_uncorrected and ecc_uncorrected > 0) or (ecc_corrected and ecc_corrected > 100):
                    ecc_str += " (ISSUE)"
                output.append(ecc_str)

            # Fan speed
            fan = gpu.get('fan_speed')
            if fan is not None:
                output.append(f"  Fan Speed:        {fan}%")

            # Performance state
            pstate = gpu.get('pstate')
            if pstate:
                output.append(f"  Performance State: {pstate}")

        output.append("")  # Blank line between GPUs

    return '\n'.join(output).rstrip()


def format_json(gpus, warn_only=False):
    """Format GPU data as JSON."""
    if warn_only:
        gpus = [g for g in gpus if g['status'] != 'OK']

    return json.dumps(gpus, indent=2)


def format_table(gpus, warn_only=False):
    """Format GPU data as a table."""
    if warn_only:
        gpus = [g for g in gpus if g['status'] != 'OK']

    if not gpus:
        return "No GPUs found." if not warn_only else "No warnings detected."

    # Header
    header = f"{'GPU':<5} {'NAME':<30} {'TEMP':<8} {'MEM USED':<12} {'UTIL':<8} {'POWER':<15} {'STATUS':<10}"
    separator = '-' * len(header)
    rows = [header, separator]

    for gpu in gpus:
        idx = str(gpu['index'])
        name = gpu['name'][:28] if len(gpu['name']) > 28 else gpu['name']

        temp = gpu['temperature'].get('gpu')
        temp_str = f"{temp}°C" if temp is not None else 'N/A'

        mem_used = gpu['memory'].get('used')
        mem_total = gpu['memory'].get('total')
        if mem_used is not None and mem_total is not None:
            mem_str = f"{mem_used}/{mem_total}M"
        else:
            mem_str = 'N/A'

        util = gpu['utilization'].get('gpu')
        util_str = f"{util}%" if util is not None else 'N/A'

        power_draw = gpu['power'].get('draw')
        power_limit = gpu['power'].get('limit')
        if power_draw is not None and power_limit is not None:
            power_str = f"{power_draw:.0f}W/{power_limit:.0f}W"
        else:
            power_str = 'N/A'

        status = gpu['status']

        row = f"{idx:<5} {name:<30} {temp_str:<8} {mem_str:<12} {util_str:<8} {power_str:<15} {status:<10}"
        rows.append(row)

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor GPU health and performance on baremetal systems.',
        epilog='''
Examples:
  # Show all GPU metrics
  gpu_health_monitor.py

  # Show only warnings and critical issues
  gpu_health_monitor.py --warn-only

  # Output as JSON for monitoring systems
  gpu_health_monitor.py --format json

  # Verbose output with power, clocks, and ECC details
  gpu_health_monitor.py --verbose

  # Table format for quick overview
  gpu_health_monitor.py --format table

Exit codes:
  0 - All GPUs healthy
  1 - Warning or critical issues detected
  2 - Usage error or missing dependencies
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show GPUs with warnings or critical status'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information (power, clocks, ECC errors)'
    )

    args = parser.parse_args()

    # Check if nvidia-smi is available
    if not check_nvidia_smi_available():
        print("Error: 'nvidia-smi' command not found.", file=sys.stderr)
        print("Ensure NVIDIA drivers are installed and nvidia-smi is in PATH.", file=sys.stderr)
        print("For driver installation, see: https://docs.nvidia.com/datacenter/tesla/tesla-installation-notes/", file=sys.stderr)
        return 2

    # Get GPU data
    gpus = get_gpu_data()

    if not gpus:
        print("No NVIDIA GPUs detected.", file=sys.stderr)
        return 1

    # Format output
    if args.format == 'json':
        output = format_json(gpus, args.warn_only)
    elif args.format == 'table':
        output = format_table(gpus, args.warn_only)
    else:
        output = format_plain(gpus, args.warn_only, args.verbose)

    print(output)

    # Determine exit code based on GPU status
    has_warnings = any(g['status'] == 'WARNING' for g in gpus)
    has_critical = any(g['status'] == 'CRITICAL' for g in gpus)

    if has_critical or has_warnings:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
