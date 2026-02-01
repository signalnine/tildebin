#!/usr/bin/env python3
"""
Predict disk failure risk using SMART attribute trend analysis.

Analyzes critical SMART attributes (reallocated sectors, pending sectors,
uncorrectable errors, etc.) and their historical trends to estimate failure
risk. Complements disk_health_check.py with predictive maintenance capabilities.

Key features:
- Analyzes critical SMART attributes that indicate pending failure
- Provides risk scoring based on attribute severity
- Supports both SATA/SAS (smartctl) and NVMe drives
- Outputs actionable recommendations

Exit codes:
    0 - All disks healthy (low risk)
    1 - Warnings detected (medium/high risk disks found)
    2 - Missing dependency or usage error
"""

import argparse
import subprocess
import sys
import json
import re


# SMART attributes that indicate potential failure
# Format: (attribute_id, name, weight, threshold_warn, threshold_critical)
CRITICAL_ATTRIBUTES = {
    # Reallocated sectors - bad sectors remapped to spare area
    '5': {'name': 'Reallocated_Sector_Ct', 'weight': 10, 'warn': 1, 'critical': 10},
    # Spin retry count - spinup failures
    '10': {'name': 'Spin_Retry_Count', 'weight': 8, 'warn': 1, 'critical': 5},
    # Reallocated event count
    '196': {'name': 'Reallocated_Event_Count', 'weight': 9, 'warn': 1, 'critical': 5},
    # Current pending sectors waiting to be remapped
    '197': {'name': 'Current_Pending_Sector', 'weight': 10, 'warn': 1, 'critical': 5},
    # Offline uncorrectable sectors
    '198': {'name': 'Offline_Uncorrectable', 'weight': 10, 'warn': 1, 'critical': 5},
    # UDMA CRC errors - cable/connection issues
    '199': {'name': 'UDMA_CRC_Error_Count', 'weight': 3, 'warn': 10, 'critical': 100},
    # Reported uncorrectable errors
    '187': {'name': 'Reported_Uncorrect', 'weight': 8, 'warn': 1, 'critical': 10},
    # Command timeout
    '188': {'name': 'Command_Timeout', 'weight': 5, 'warn': 5, 'critical': 50},
    # High fly writes (head positioning issues)
    '189': {'name': 'High_Fly_Writes', 'weight': 4, 'warn': 1, 'critical': 10},
    # G-sense error rate (shock sensor)
    '191': {'name': 'G-Sense_Error_Rate', 'weight': 3, 'warn': 10, 'critical': 100},
    # Power off retract count
    '192': {'name': 'Power-Off_Retract_Count', 'weight': 2, 'warn': 100, 'critical': 1000},
    # Load cycle count
    '193': {'name': 'Load_Cycle_Count', 'weight': 2, 'warn': 300000, 'critical': 500000},
}

# Risk level thresholds (based on weighted score)
RISK_LOW = 10
RISK_MEDIUM = 30
RISK_HIGH = 60


def run_command(cmd, shell=False):
    """Execute a command and return output"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def check_smartctl_available():
    """Check if smartctl is installed"""
    returncode, _, _ = run_command(['which', 'smartctl'])
    return returncode == 0


def get_disk_list():
    """Get list of disk devices (excluding partitions)"""
    returncode, stdout, stderr = run_command(
        "lsblk -d -n -o NAME,TYPE | grep disk | awk '{print $1}'",
        shell=True
    )
    if returncode != 0:
        return []

    disks = []
    for disk in stdout.strip().split('\n'):
        if disk.strip():
            disks.append("/dev/{}".format(disk.strip()))
    return disks


def get_disk_info(disk):
    """Get basic disk information"""
    returncode, stdout, stderr = run_command(
        "lsblk -n -o SIZE,MODEL {} | head -1".format(disk),
        shell=True
    )

    if returncode != 0:
        return "N/A", "N/A"

    parts = stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"

    return size, model


def is_nvme_device(disk):
    """Check if disk is NVMe"""
    return 'nvme' in disk.lower()


def get_smart_attributes(disk):
    """Get SMART attributes for a SATA/SAS disk"""
    returncode, stdout, stderr = run_command(['smartctl', '-A', disk])

    if returncode not in [0, 4]:  # 4 = SMART threshold exceeded
        return None, "Unable to read SMART data"

    attributes = {}

    for line in stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 10:
            attr_id = parts[0]
            if attr_id in CRITICAL_ATTRIBUTES:
                try:
                    raw_value = int(parts[9].split()[0])  # Handle "123 (N/A)" format
                    attributes[attr_id] = {
                        'name': CRITICAL_ATTRIBUTES[attr_id]['name'],
                        'raw_value': raw_value
                    }
                except (ValueError, IndexError):
                    pass

    return attributes, None


def get_nvme_smart_data(disk):
    """Get SMART data for NVMe disk"""
    returncode, stdout, stderr = run_command(['nvme', 'smart-log', disk, '-o', 'json'])

    if returncode != 0:
        # Try without JSON output
        returncode, stdout, stderr = run_command(['nvme', 'smart-log', disk])
        if returncode != 0:
            return None, "Unable to read NVMe SMART log"

        # Parse text output
        data = {}
        for line in stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                if 'percentage_used' in key:
                    match = re.search(r'(\d+)', value)
                    if match:
                        data['percentage_used'] = int(match.group(1))
                elif 'media' in key and 'error' in key:
                    match = re.search(r'(\d+)', value)
                    if match:
                        data['media_errors'] = int(match.group(1))
                elif 'available_spare' in key and 'threshold' not in key:
                    match = re.search(r'(\d+)', value)
                    if match:
                        data['available_spare'] = int(match.group(1))

        return data, None

    try:
        data = json.loads(stdout)
        return data, None
    except json.JSONDecodeError:
        return None, "Failed to parse NVMe SMART JSON"


def get_smart_health_status(disk):
    """Get overall SMART health status"""
    returncode, stdout, stderr = run_command(['smartctl', '-H', disk])

    if "SMART support is: Unavailable" in stdout or "SMART support is: Disabled" in stdout:
        return "UNAVAILABLE"

    if "PASSED" in stdout:
        return "PASSED"
    elif "FAILED" in stdout:
        return "FAILED"
    return "UNKNOWN"


def calculate_risk_score(attributes, is_nvme=False, nvme_data=None):
    """Calculate risk score based on SMART attributes"""
    total_score = 0
    findings = []

    if is_nvme and nvme_data:
        # NVMe risk calculation
        wear = nvme_data.get('percentage_used', 0)
        if wear >= 90:
            total_score += 50
            findings.append(("CRITICAL", "Wear level at {}%".format(wear)))
        elif wear >= 80:
            total_score += 30
            findings.append(("WARNING", "Wear level at {}%".format(wear)))
        elif wear >= 70:
            total_score += 15
            findings.append(("INFO", "Wear level at {}%".format(wear)))

        media_errors = nvme_data.get('media_errors', nvme_data.get('media_and_data_integrity_errors', 0))
        if media_errors > 0:
            total_score += 40
            findings.append(("CRITICAL", "{} media errors detected".format(media_errors)))

        spare = nvme_data.get('available_spare', 100)
        if spare < 10:
            total_score += 30
            findings.append(("CRITICAL", "Available spare at {}%".format(spare)))
        elif spare < 25:
            total_score += 15
            findings.append(("WARNING", "Available spare at {}%".format(spare)))

    else:
        # SATA/SAS risk calculation
        if attributes is None:
            return 100, [("CRITICAL", "Unable to read SMART data")]

        for attr_id, attr_data in attributes.items():
            config = CRITICAL_ATTRIBUTES.get(attr_id)
            if not config:
                continue

            raw_value = attr_data['raw_value']
            weight = config['weight']
            warn_thresh = config['warn']
            crit_thresh = config['critical']

            if raw_value >= crit_thresh:
                score = weight * 5
                total_score += score
                findings.append((
                    "CRITICAL",
                    "{}: {} (critical >= {})".format(
                        attr_data['name'], raw_value, crit_thresh
                    )
                ))
            elif raw_value >= warn_thresh:
                score = weight * 2
                total_score += score
                findings.append((
                    "WARNING",
                    "{}: {} (warn >= {})".format(
                        attr_data['name'], raw_value, warn_thresh
                    )
                ))

    return total_score, findings


def get_risk_level(score):
    """Convert numeric score to risk level"""
    if score >= RISK_HIGH:
        return "HIGH"
    elif score >= RISK_MEDIUM:
        return "MEDIUM"
    elif score >= RISK_LOW:
        return "LOW"
    return "MINIMAL"


def get_recommendation(risk_level, findings):
    """Generate actionable recommendation based on risk"""
    if risk_level == "HIGH":
        return "IMMEDIATE ACTION: Back up data and plan disk replacement"
    elif risk_level == "MEDIUM":
        return "Schedule disk replacement within 30 days; verify backups"
    elif risk_level == "LOW":
        return "Monitor closely; ensure backups are current"
    return "No action required; continue regular monitoring"


def analyze_disk(disk):
    """Analyze a single disk and return results"""
    size, model = get_disk_info(disk)
    is_nvme = is_nvme_device(disk)

    result = {
        'disk': disk,
        'size': size,
        'model': model,
        'type': 'NVMe' if is_nvme else 'SATA/SAS',
        'smart_status': 'N/A',
        'risk_score': 0,
        'risk_level': 'MINIMAL',
        'findings': [],
        'recommendation': ''
    }

    if is_nvme:
        nvme_data, error = get_nvme_smart_data(disk)
        if error:
            result['findings'] = [("ERROR", error)]
            result['risk_score'] = 100
            result['risk_level'] = "HIGH"
            result['recommendation'] = "Unable to assess: " + error
            return result

        result['smart_status'] = "PASSED"  # NVMe doesn't have simple pass/fail
        result['nvme_data'] = nvme_data

        score, findings = calculate_risk_score(None, is_nvme=True, nvme_data=nvme_data)

    else:
        result['smart_status'] = get_smart_health_status(disk)

        if result['smart_status'] == "FAILED":
            result['risk_score'] = 100
            result['risk_level'] = "HIGH"
            result['findings'] = [("CRITICAL", "SMART overall health test FAILED")]
            result['recommendation'] = get_recommendation("HIGH", result['findings'])
            return result

        if result['smart_status'] == "UNAVAILABLE":
            result['findings'] = [("INFO", "SMART not available for this disk")]
            result['recommendation'] = "Cannot assess; SMART unavailable"
            return result

        attributes, error = get_smart_attributes(disk)
        if error:
            result['findings'] = [("ERROR", error)]
            return result

        result['attributes'] = attributes
        score, findings = calculate_risk_score(attributes)

    result['risk_score'] = score
    result['risk_level'] = get_risk_level(score)
    result['findings'] = findings
    result['recommendation'] = get_recommendation(result['risk_level'], findings)

    return result


def format_output_plain(results, warn_only, verbose):
    """Format output as plain text"""
    for result in results:
        if warn_only and result['risk_level'] == "MINIMAL":
            continue

        risk_symbol = {
            'MINIMAL': '[OK]',
            'LOW': '[LOW]',
            'MEDIUM': '[MED]',
            'HIGH': '[!!!]'
        }.get(result['risk_level'], '[???]')

        print("{} {} ({}) - {} {}".format(
            risk_symbol,
            result['disk'],
            result['type'],
            result['size'],
            result['model']
        ))

        print("    Risk: {} (score: {})".format(
            result['risk_level'],
            result['risk_score']
        ))

        if result['findings']:
            for severity, message in result['findings']:
                print("    {}: {}".format(severity, message))

        if verbose or result['risk_level'] != "MINIMAL":
            print("    Recommendation: {}".format(result['recommendation']))

        print()


def format_output_table(results, warn_only):
    """Format output as table"""
    if warn_only:
        results = [r for r in results if r['risk_level'] != "MINIMAL"]

    if not results:
        print("No disks with elevated risk found")
        return

    print("{:<15} {:<8} {:<8} {:<8} {:<8} {}".format(
        "Disk", "Type", "Size", "Risk", "Score", "Findings"
    ))
    print("-" * 75)

    for result in results:
        disk_name = result['disk'].replace('/dev/', '')
        finding_count = len(result['findings'])
        findings_str = "{} issue(s)".format(finding_count) if finding_count else "OK"

        print("{:<15} {:<8} {:<8} {:<8} {:<8} {}".format(
            disk_name,
            result['type'],
            result['size'],
            result['risk_level'],
            result['risk_score'],
            findings_str
        ))


def format_output_json(results):
    """Format output as JSON"""
    # Convert findings tuples to dicts for JSON
    json_results = []
    for result in results:
        json_result = result.copy()
        json_result['findings'] = [
            {'severity': sev, 'message': msg}
            for sev, msg in result['findings']
        ]
        # Remove internal data structures
        json_result.pop('attributes', None)
        json_result.pop('nvme_data', None)
        json_results.append(json_result)

    print(json.dumps(json_results, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Predict disk failure risk using SMART attribute analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Risk Levels:
  MINIMAL  - No concerning indicators (score < 10)
  LOW      - Minor indicators, monitor closely (score 10-29)
  MEDIUM   - Elevated risk, plan replacement (score 30-59)
  HIGH     - Imminent failure likely, replace ASAP (score >= 60)

Examples:
  %(prog)s                    # Check all disks
  %(prog)s -d /dev/sda        # Check specific disk
  %(prog)s --format json      # JSON output for automation
  %(prog)s --warn-only        # Only show disks with elevated risk
"""
    )

    parser.add_argument(
        "-d", "--disk",
        help="Specific disk to check (e.g., /dev/sda)"
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
        help="Show detailed information for all disks"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show disks with elevated risk (LOW or higher)"
    )

    args = parser.parse_args()

    # Check for smartctl
    if not check_smartctl_available():
        print("Error: smartctl not found", file=sys.stderr)
        print("Install with: sudo apt-get install smartmontools", file=sys.stderr)
        sys.exit(2)

    # Get disk list
    if args.disk:
        disks = [args.disk]
    else:
        disks = get_disk_list()

    if not disks:
        print("No disks found", file=sys.stderr)
        sys.exit(2)

    # Analyze disks
    results = []
    has_warnings = False

    for disk in disks:
        result = analyze_disk(disk)
        results.append(result)

        if result['risk_level'] != "MINIMAL":
            has_warnings = True

    # Output results
    if args.format == "json":
        format_output_json(results)
    elif args.format == "table":
        format_output_table(results, args.warn_only)
    else:
        format_output_plain(results, args.warn_only, args.verbose)

    # Exit with appropriate code
    sys.exit(1 if has_warnings else 0)


if __name__ == "__main__":
    main()
