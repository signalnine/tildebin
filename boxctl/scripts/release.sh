#!/bin/bash
# Create a new release version

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.2.0"
    echo ""
    echo "This will:"
    echo "  1. Update version in pyproject.toml"
    echo "  2. Update version in boxctl/__init__.py"
    echo "  3. Create a git commit"
    echo "  4. Create a git tag"
    exit 1
fi

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 0.2.0)"
    exit 1
fi

cd "$PROJECT_DIR"

# Check for uncommitted changes
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Error: Working directory has uncommitted changes"
    echo "Please commit or stash changes before releasing"
    exit 1
fi

# Update version in pyproject.toml
echo "Updating pyproject.toml..."
sed -i "s/^version = .*/version = \"$VERSION\"/" pyproject.toml

# Update version in __init__.py
echo "Updating boxctl/__init__.py..."
sed -i "s/^__version__ = .*/__version__ = \"$VERSION\"/" boxctl/__init__.py

# Verify the changes
echo ""
echo "Version updated to $VERSION:"
grep "^version = " pyproject.toml
grep "^__version__ = " boxctl/__init__.py

# Commit and tag
echo ""
echo "Creating commit and tag..."
git add pyproject.toml boxctl/__init__.py
git commit -m "chore: release v$VERSION"
git tag "v$VERSION"

echo ""
echo "✓ Created tag v$VERSION"
echo ""
echo "To publish the release, run:"
echo "  git push && git push --tags"
echo ""
echo "This will trigger the GitHub Actions release workflow."
