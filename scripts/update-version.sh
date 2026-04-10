#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

usage() {
    cat << EOF
Usage: $0 <version>

Update version numbers in all package files.

Arguments:
    version    Semantic version (e.g., 0.2.0)

Example:
    $0 0.2.0    # Update version to 0.2.0
EOF
    exit 1
}

# Parse arguments
if [[ $# -ne 1 ]]; then
    usage
fi

VERSION="$1"

# Validate version format
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be semantic version (e.g., 0.2.0)"
    exit 1
fi

echo "Updating version to $VERSION..."

# Update Cargo.toml
sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
echo "  - Cargo.toml"

# Update Flatpak manifest
sed -i "s/^app-version:.*/app-version: '$VERSION'/" packaging/org.perms.app.yml
echo "  - packaging/org.perms.app.yml"

# Update metainfo
sed -i "s/<release version=\"[^\"]*\"/<release version=\"$VERSION\"/" packaging/org.perms.app.metainfo.xml
sed -i "s/date=\"[^\"]*\"/date=\"$(date +%Y-%m-%d)\"/" packaging/org.perms.app.metainfo.xml
echo "  - packaging/org.perms.app.metainfo.xml"

# Update PKGBUILD
sed -i "s/^pkgver=.*/pkgver=$VERSION/" packaging/PKGBUILD
echo "  - packaging/PKGBUILD"

echo ""
echo "Version updated to $VERSION"
echo "Run 'git diff' to see changes"
