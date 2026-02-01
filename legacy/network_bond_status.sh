#!/bin/bash
# Check status of network bonded interfaces

set -e

# Colors for output (if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    GREEN=''
    RED=''
    YELLOW=''
    NC=''
fi

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Check status of network bonded interfaces.

OPTIONS:
    -b, --bond NAME     Check specific bond interface
    -v, --verbose       Show detailed information
    -j, --json          Output in JSON format
    -h, --help          Show this help message

EXAMPLES:
    $(basename "$0")                    # Check all bonds
    $(basename "$0") -b bond0           # Check specific bond
    $(basename "$0") -v                 # Verbose output
EOF
}

check_bond_exists() {
    local bond=$1
    if [ ! -d "/proc/net/bonding/$bond" ]; then
        return 1
    fi
    return 0
}

get_bond_list() {
    if [ -d /proc/net/bonding ]; then
        ls /proc/net/bonding 2>/dev/null || echo ""
    else
        echo ""
    fi
}

parse_bond_info() {
    local bond=$1
    local bonding_file="/proc/net/bonding/$bond"

    if [ ! -f "$bonding_file" ]; then
        echo "Bond $bond not found"
        return 1
    fi

    # Extract bond information
    mode=$(grep "Bonding Mode:" "$bonding_file" | cut -d: -f2 | xargs)
    mii_status=$(grep "MII Status:" "$bonding_file" | head -1 | cut -d: -f2 | xargs)

    # Count active and total slaves
    total_slaves=$(grep -c "Slave Interface:" "$bonding_file" || echo "0")
    active_slaves=$(grep "MII Status:" "$bonding_file" | grep -c "up" || echo "0")

    # Get slave details
    slave_info=""
    if [ "$VERBOSE" = "true" ]; then
        slave_info=$(awk '
            /Slave Interface:/ { iface=$3; getline }
            /MII Status:/ {
                status=$3
                print "  " iface ": " status
            }
        ' "$bonding_file")
    fi

    # Determine overall status
    if [ "$mii_status" = "up" ] && [ "$active_slaves" -gt 0 ]; then
        status="ACTIVE"
        color=$GREEN
    elif [ "$active_slaves" -gt 0 ] && [ "$active_slaves" -lt "$total_slaves" ]; then
        status="DEGRADED"
        color=$YELLOW
    else
        status="DOWN"
        color=$RED
    fi

    if [ "$JSON_OUTPUT" = "true" ]; then
        cat << JSONEOF
{
  "interface": "$bond",
  "status": "$status",
  "mode": "$mode",
  "mii_status": "$mii_status",
  "total_slaves": $total_slaves,
  "active_slaves": $active_slaves
}
JSONEOF
    else
        echo -e "${color}[${status}]${NC} $bond - Mode: $mode - Slaves: $active_slaves/$total_slaves active"
        if [ "$VERBOSE" = "true" ]; then
            echo "$slave_info"
            echo ""
        fi
    fi
}

# Parse command line arguments
SPECIFIC_BOND=""
VERBOSE=false
JSON_OUTPUT=false

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--bond)
            SPECIFIC_BOND="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -j|--json)
            JSON_OUTPUT=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
if [ "$SPECIFIC_BOND" != "" ]; then
    # Check specific bond
    if ! check_bond_exists "$SPECIFIC_BOND"; then
        echo "Error: Bond interface '$SPECIFIC_BOND' not found"
        exit 1
    fi
    parse_bond_info "$SPECIFIC_BOND"
else
    # Check all bonds
    bonds=$(get_bond_list)

    if [ -z "$bonds" ]; then
        echo "No bonded interfaces found"
        echo ""
        echo "To create a bond interface, configure /etc/network/interfaces or use nmcli:"
        echo "  nmcli con add type bond ifname bond0 mode active-backup"
        echo "  nmcli con add type ethernet ifname eth0 master bond0"
        exit 0
    fi

    if [ "$JSON_OUTPUT" = "true" ]; then
        echo "["
        first=true
        for bond in $bonds; do
            if [ "$first" = false ]; then
                echo ","
            fi
            parse_bond_info "$bond"
            first=false
        done
        echo "]"
    else
        echo "Network Bond Status:"
        echo "===================="
        echo ""
        for bond in $bonds; do
            parse_bond_info "$bond"
        done
    fi
fi

exit 0
