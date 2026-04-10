#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
    cat << EOF
Usage: $0 <version> [options]

Create a new release with AppImage and Flatpak packages.

Arguments:
    version                 Semantic version (e.g., 0.2.0)

Options:
    --skip-build            Skip building (just update versions)
    --skip-flatpak          Skip Flatpak build
    --skip-appimage         Skip AppImage build
    --dry-run               Show what would be done without doing it
    -h, --help              Show this help

Environment:
    GITHUB_TOKEN            GitHub personal access token (required for release)

Examples:
    $0 0.2.0                # Release version 0.2.0
    $0 1.0.0 --skip-flatpak # Release without Flatpak
EOF
    exit 1
}

# Parse arguments
VERSION=""
SKIP_BUILD=false
SKIP_FLATPAK=false
SKIP_APPIMAGE=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build|--skip-flatpak|--skip-appimage|--dry-run)
            [[ "$1" == "--skip-build" ]] && SKIP_BUILD=true
            [[ "$1" == "--skip-flatpak" ]] && SKIP_FLATPAK=true
            [[ "$1" == "--skip-appimage" ]] && SKIP_APPIMAGE=true
            [[ "$1" == "--dry-run" ]] && DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                echo "Error: Unknown argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

# Validate version format (semantic versioning)
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be semantic version (e.g., 0.2.0)"
    exit 1
fi

# Check for GitHub token
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo "Error: GITHUB_TOKEN environment variable not set"
    echo "Create a token at: https://github.com/settings/tokens"
    echo "Required scopes: repo"
    exit 1
fi

echo "=========================================="
echo "  perms Release Script v$VERSION"
echo "=========================================="
echo ""

# Update version in Cargo.toml
update_version_in_cargo() {
    local new_version="$1"
    local file="Cargo.toml"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY RUN] Would update version to $new_version in $file"
        return
    fi
    
    sed -i "s/^version = \".*\"/version = \"$new_version\"/" "$file"
    echo "Updated version to $new_version in $file"
}

# Update version in Flatpak manifest
update_version_in_flatpak_manifest() {
    local new_version="$1"
    local file="packaging/org.perms.app.yml"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY RUN] Would update version to $new_version in $file"
        return
    fi
    
    sed -i "s/^  app-version:.*/  app-version: '$new_version'/" "$file" 2>/dev/null || true
    echo "Updated version to $new_version in $file"
}

# Update version in metainfo
update_version_in_metainfo() {
    local new_version="$1"
    local file="packaging/org.perms.app.metainfo.xml"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY RUN] Would update version to $new_version in $file"
        return
    fi
    
    sed -i "s/<release version=\"[^\"]*\"/<release version=\"$new_version\"/" "$file"
    sed -i "s/date=\"[^\"]*\"/date=\"$(date +%Y-%m-%d)\"/" "$file"
    echo "Updated version to $new_version in $file"
}

# Update version in PKGBUILD
update_version_in_pkgbuild() {
    local new_version="$1"
    local file="packaging/PKGBUILD"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY RUN] Would update version to $new_version in $file"
        return
    fi
    
    sed -i "s/^pkgver=.*/pkgver=$new_version/" "$file"
    echo "Updated version to $new_version in $file"
}

echo "Step 1: Updating version numbers..."
update_version_in_cargo "$VERSION"
update_version_in_flatpak_manifest "$VERSION"
update_version_in_metainfo "$VERSION"
update_version_in_pkgbuild "$VERSION"
echo ""

# Commit changes
if [[ "$DRY_RUN" == false ]]; then
    echo "Step 2: Committing version bump..."
    git add -A
    git commit -m "release: bump version to $VERSION"
    git tag -a "v$VERSION" -m "Release $VERSION"
    echo "Committed and tagged v$VERSION"
    echo ""
fi

# Build AppImage
build_appimage() {
    local output_file="packaging/perms-${VERSION}-x86_64.AppImage"
    
    if [[ "$SKIP_APPIMAGE" == true ]]; then
        echo "Skipping AppImage build"
        return
    fi
    
    echo "Step 3: Building AppImage..."
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY RUN] Would build AppImage: $output_file"
        return
    fi
    
    # Build release binary
    cargo build --release --locked
    
    # Create AppDir
    rm -rf AppDir
    mkdir -p AppDir/usr/bin
    mkdir -p AppDir/usr/libexec
    mkdir -p AppDir/usr/share/polkit-1/actions
    mkdir -p AppDir/usr/share/icons/hicolor/256x256/apps
    mkdir -p AppDir/usr/share/pixmaps
    
    # Copy binaries
    install -m755 target/release/perms-ui AppDir/usr/bin/perms
    install -m755 target/release/perms-helper AppDir/usr/libexec/perms-helper
    install -m644 packaging/org.perms.helper.policy AppDir/usr/share/polkit-1/actions/org.perms.helper.policy
    
    install -Dm644 "icon/batch_Page 1.png" AppDir/usr/share/icons/hicolor/512x512/apps/org.perms.app.png
    install -Dm644 "icon/batch_Page 1.svg" AppDir/usr/share/icons/hicolor/scalable/apps/org.perms.app.svg
    install -Dm644 packaging/org.perms.app.desktop AppDir/perms.desktop
    sed -i 's/^Exec=.*/Exec=perms/' AppDir/perms.desktop
    sed -i 's/^Icon=.*/Icon=org.perms.app/' AppDir/perms.desktop
    cp "icon/batch_Page 1.png" AppDir/.DirIcon
    cp "icon/batch_Page 1.png" AppDir/perms.png
    
    # Create AppRun
    cat > AppDir/AppRun << 'APPRUN'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"
exec "${HERE}/usr/bin/perms" "$@"
APPRUN
    chmod +x AppDir/AppRun
    
    # Build AppImage using appimagetool
    if [[ ! -f /tmp/appimagetool ]]; then
        curl -L https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage -o /tmp/appimagetool
        chmod +x /tmp/appimagetool
    fi
    if [[ ! -f /tmp/runtime-x86_64 ]]; then
        curl -L https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-x86_64 -o /tmp/runtime-x86_64
        chmod +x /tmp/runtime-x86_64
    fi
    
    /tmp/appimagetool --runtime-file /tmp/runtime-x86_64 AppDir "$output_file"
    rm -rf AppDir
    
    echo "AppImage built: $output_file"
}

# Build Flatpak
build_flatpak() {
    local output_file="packaging/org.perms.app.flatpak"
    
    if [[ "$SKIP_FLATPAK" == true ]]; then
        echo "Skipping Flatpak build"
        return
    fi
    
    echo "Step 4: Building Flatpak..."
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY RUN] Would build Flatpak: $output_file"
        return
    fi
    
    # Vendor dependencies
    cargo vendor vendor 2>/dev/null || true
    
    # Setup cargo config for flatpak
    mkdir -p .cargo
    cat > .cargo/config.toml << 'CARGO_CONFIG'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
CARGO_CONFIG
    
    # Setup flatpak build directory
    rm -rf /tmp/flatpak-build
    
    # Build using flatpak-builder
    if command -v flatpak-builder &>/dev/null; then
        flatpak-builder --repo=/tmp/flatpak-repo /tmp/flatpak-build packaging/org.perms.app.yml
        
        # Create bundle
        flatpak build-bundle ~/.local/share/flatpak/repo "$output_file" org.perms.app 2>/dev/null || \
        flatpak build-export /tmp/flatpak-repo /tmp/flatpak-build && \
        flatpak build-bundle /tmp/flatpak-repo "$output_file" org.perms.app
    else
        echo "Warning: flatpak-builder not found, skipping Flatpak build"
        SKIP_FLATPAK=true
    fi
    
    # Cleanup
    rm -rf vendor .cargo/config.toml
    
    if [[ "$SKIP_FLATPAK" == false ]]; then
        echo "Flatpak built: $output_file"
    fi
}

# Create GitHub release
create_github_release() {
    local output_dir="packaging"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY RUN] Would create GitHub release v$VERSION"
        return
    fi
    
    echo "Step 5: Creating GitHub release..."
    
    # Collect artifacts
    local appimage="$output_dir/perms-${VERSION}-x86_64.AppImage"
    local flatpak="$output_dir/org.perms.app.flatpak"
    
    # Create release body
    local release_notes="## Release $VERSION

### Downloads
"
    [[ -f "$appimage" ]] && release_notes+="- **AppImage**: perms-${VERSION}-x86_64.AppImage\n"
    [[ -f "$flatpak" ]] && release_notes+="- **Flatpak**: org.perms.app.flatpak\n"
    
    release_notes+="
### Installation

#### AppImage
\`\`\`bash
chmod +x perms-${VERSION}-x86_64.AppImage
./perms-${VERSION}-x86_64.AppImage
\`\`\`

#### Flatpak
\`\`\`bash
flatpak install org.perms.app.flatpak
flatpak run org.perms.app
\`\`\`

### What's New
See CHANGELOG.md for details.
"
    
    # Create release using gh
    if [[ -f "$flatpak" ]]; then
        gh release create "v$VERSION" "$appimage" "$flatpak" \
            --title "Release $VERSION" \
            --notes "$release_notes" \
            --repo "$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')"
    elif [[ -f "$appimage" ]]; then
        gh release create "v$VERSION" "$appimage" \
            --title "Release $VERSION" \
            --notes "$release_notes" \
            --repo "$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')"
    else
        gh release create "v$VERSION" \
            --title "Release $VERSION" \
            --notes "$release_notes" \
            --repo "$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')"
    fi
    
    echo "Release created: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/releases/tag/v$VERSION"
}

# Main execution
if [[ "$SKIP_BUILD" == false ]]; then
    build_appimage
    build_flatpak
fi

create_github_release

echo ""
echo "=========================================="
echo "  Release v$VERSION complete!"
echo "=========================================="
