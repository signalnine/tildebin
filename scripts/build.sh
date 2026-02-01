#!/bin/bash
# Build boxctl distribution with bundled Python runtime

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
DIST_DIR="$PROJECT_DIR/dist"

# Configuration - uses python-build-standalone
PYTHON_VERSION="${PYTHON_VERSION:-3.12.8}"
PYTHON_BUILD_DATE="${PYTHON_BUILD_DATE:-20250317}"
ARCH="${ARCH:-x86_64}"
PLATFORM="${PLATFORM:-unknown-linux-gnu}"

# Construct URL for python-build-standalone
PYTHON_URL="https://github.com/indygreg/python-build-standalone/releases/download/${PYTHON_BUILD_DATE}/cpython-${PYTHON_VERSION}+${PYTHON_BUILD_DATE}-${ARCH}-${PLATFORM}-install_only.tar.gz"

echo "Building boxctl distribution..."
echo "Python: ${PYTHON_VERSION}"
echo "Platform: ${ARCH}-${PLATFORM}"
echo ""

# Clean previous builds
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

# Download Python runtime
echo "Downloading Python runtime..."
PYTHON_TARBALL="$BUILD_DIR/python.tar.gz"
if ! curl -fSL "$PYTHON_URL" -o "$PYTHON_TARBALL"; then
    echo "ERROR: Failed to download Python runtime"
    echo "URL: $PYTHON_URL"
    echo ""
    echo "Check available releases at:"
    echo "https://github.com/indygreg/python-build-standalone/releases"
    exit 1
fi

# Extract runtime
echo "Extracting Python runtime..."
mkdir -p "$BUILD_DIR/runtime"
tar xzf "$PYTHON_TARBALL" -C "$BUILD_DIR/runtime" --strip-components=1

# Install dependencies into runtime
echo "Installing dependencies..."
"$BUILD_DIR/runtime/bin/pip" install --quiet pyyaml

# Install boxctl core
echo "Installing boxctl..."
"$BUILD_DIR/runtime/bin/pip" install --quiet "$PROJECT_DIR"

# Copy scripts (if they exist)
echo "Copying scripts..."
mkdir -p "$BUILD_DIR/scripts"
for dir in baremetal k8s; do
    if [ -d "$PROJECT_DIR/scripts/$dir" ]; then
        cp -r "$PROJECT_DIR/scripts/$dir" "$BUILD_DIR/scripts/"
    fi
done

# Copy profiles (if they exist)
echo "Copying profiles..."
mkdir -p "$BUILD_DIR/profiles"
if [ -d "$PROJECT_DIR/profiles" ] && [ "$(ls -A "$PROJECT_DIR/profiles" 2>/dev/null)" ]; then
    cp -r "$PROJECT_DIR/profiles/"* "$BUILD_DIR/profiles/"
fi

# Create wrapper script
echo "Creating wrapper..."
mkdir -p "$BUILD_DIR/bin"
cat > "$BUILD_DIR/bin/boxctl" << 'WRAPPER'
#!/bin/bash
set -euo pipefail
BOXCTL_HOME="${BOXCTL_HOME:-$(dirname "$(dirname "$(readlink -f "$0")")")}"
export BOXCTL_HOME
export BOXCTL_SCRIPTS_DIR="${BOXCTL_SCRIPTS_DIR:-$BOXCTL_HOME/scripts}"
exec "$BOXCTL_HOME/runtime/bin/python3" -m boxctl "$@"
WRAPPER
chmod +x "$BUILD_DIR/bin/boxctl"

# Create version file
echo "Creating version info..."
VERSION=$(grep -Po '(?<=version = ")[^"]+' "$PROJECT_DIR/pyproject.toml" || echo "0.1.0")
cat > "$BUILD_DIR/VERSION" << EOF
boxctl ${VERSION}
Python: ${PYTHON_VERSION}
Platform: ${ARCH}-${PLATFORM}
Built: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Package full distribution
echo "Creating distribution archive..."
ARCHIVE_NAME="boxctl-${VERSION}-linux-${ARCH}.tar.gz"
tar czf "$DIST_DIR/$ARCHIVE_NAME" -C "$BUILD_DIR" .

# Create scripts-only archive (for updating scripts without full reinstall)
if [ -n "$(ls -A "$BUILD_DIR/scripts" 2>/dev/null)" ]; then
    echo "Creating scripts-only archive..."
    tar czf "$DIST_DIR/boxctl-scripts-${VERSION}.tar.gz" -C "$BUILD_DIR" scripts profiles
fi

# Show results
echo ""
echo "Build complete!"
echo ""
ls -lh "$DIST_DIR/"
echo ""
echo "To install:"
echo "  sudo mkdir -p /opt/boxctl"
echo "  sudo tar xzf $DIST_DIR/$ARCHIVE_NAME -C /opt/boxctl"
echo "  sudo ln -sf /opt/boxctl/bin/boxctl /usr/local/bin/boxctl"
