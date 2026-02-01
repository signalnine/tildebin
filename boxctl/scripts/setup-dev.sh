#!/bin/bash
# Set up boxctl development environment

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Setting up boxctl development environment..."

# Create virtual environment if needed
if [ ! -d "$PROJECT_DIR/.venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$PROJECT_DIR/.venv"
fi

# Activate and install
source "$PROJECT_DIR/.venv/bin/activate"
pip install -e ".[dev]"

echo ""
echo "Development environment ready!"
echo "Activate with: source .venv/bin/activate"
