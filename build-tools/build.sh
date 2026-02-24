#!/bin/bash
# build.sh - Rebuild Synology Active Backup for Business Agent with kernel 6.12-6.18 patches
#
# Usage:
#   ./build.sh /path/to/original-install.run              # from original .run file
#   ./build.sh /path/to/extracted-directory                # from already-extracted dir
#
# Output: install.run in current directory (or $OUTPUT_DIR if set)
#
# Requirements: dpkg-deb, tar, gzip, makeself (optional, falls back to manual)
# Must run on Linux (or WSL).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATCHES_DIR="$SCRIPT_DIR/patches"
AGENT_VERSION="3.1.0-4969"
AGENT_BUILD_TAG="4969"
SYNOSNAP_VERSION="0.11.7"
OUTPUT_DIR="${OUTPUT_DIR:-$(pwd)}"
TEMP_DIR="${TEMP_DIR:-/tmp}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# --- Validate input ---
if [ $# -lt 1 ]; then
    echo "Usage: $0 <original-install.run | extracted-directory>"
    echo ""
    echo "Examples:"
    echo "  $0 ./install.run"
    echo "  $0 ./Synology\\ Active\\ Backup\\ for\\ Business\\ Agent-3.1.0-4967-x64-deb/extracted"
    exit 1
fi

INPUT="$1"
WORKDIR=$(mktemp -d "$TEMP_DIR/abb-rebuild.XXXXXX")
trap 'rm -rf "$WORKDIR"' EXIT

info "Work directory: $WORKDIR"

# --- Step 1: Get extracted directory ---
if [ -d "$INPUT" ]; then
    # Input is a directory — check if it looks like the extracted payload
    if [ -f "$INPUT/install.sh" ] && [ -f "$INPUT/variables.sh" ]; then
        EXTRACTED="$INPUT"
        info "Using provided extracted directory: $EXTRACTED"
    elif [ -d "$INPUT/extracted" ]; then
        EXTRACTED="$INPUT/extracted"
        info "Using extracted subdirectory: $EXTRACTED"
    else
        fail "Directory doesn't look like an extracted installer. Expected install.sh + variables.sh"
    fi
elif [ -f "$INPUT" ]; then
    info "Extracting original install.run..."
    EXTRACTED="$WORKDIR/extracted"
    mkdir -p "$EXTRACTED"

    # The Synology .run is a shell script header + gzipped tar payload.
    # Find the line with __ARCHIVE_BELOW__ or the end of the shell header.
    # The original uses makeself-style format: skip N lines of shell header.
    SKIP_LINES=$(awk '/^__ARCHIVE_BELOW__/{print NR+1; exit}' "$INPUT" 2>/dev/null || true)

    if [ -n "$SKIP_LINES" ]; then
        tail -n+"$SKIP_LINES" "$INPUT" | tar xzf - -C "$EXTRACTED"
    else
        # Makeself format: offset is at a fixed line count in the header
        # Try to find the offset by looking for the payload marker
        SCRIPT_END_LINE=$(grep -a -n 'eval $finish; exit $res' "$INPUT" | sed -r 's/^([0-9]+?)\:.+$/\1/')
        OFFSET=$(head -n $SCRIPT_END_LINE "$INPUT" | wc -c | tr -d ' ')
        dd if="$INPUT" bs="$OFFSET" skip=1 2>/dev/null | gzip -cd | tar xf - -C "$EXTRACTED"
    fi

    if [ ! -f "$EXTRACTED/install.sh" ]; then
        fail "Extraction failed — install.sh not found in payload"
    fi
    ok "Extracted installer payload"
else
    fail "Input '$INPUT' is neither a file nor a directory"
fi

# --- Locate the original DEBs ---
ORIG_AGENT_DEB=$(find "$EXTRACTED" -maxdepth 1 -name "Synology Active Backup for Business Agent-3.1.0-*.deb" | head -1)
ORIG_SYNOSNAP_DEB=$(find "$EXTRACTED" -maxdepth 1 -name "synosnap-*.deb" | head -1)

[ -z "$ORIG_AGENT_DEB" ] && fail "Original agent DEB not found in $EXTRACTED"
[ -z "$ORIG_SYNOSNAP_DEB" ] && fail "Original synosnap DEB not found in $EXTRACTED"

info "Original agent DEB: $(basename "$ORIG_AGENT_DEB")"
info "Original synosnap DEB: $(basename "$ORIG_SYNOSNAP_DEB")"

# --- Step 2: Repackage synosnap DEB with patched sources ---
info "Repacking synosnap DEB with kernel 6.12 patches..."

SNAP_WORK="$WORKDIR/synosnap_repack"
mkdir -p "$SNAP_WORK"

dpkg-deb -R "$ORIG_SYNOSNAP_DEB" "$SNAP_WORK/repack"
chmod 0755 "$SNAP_WORK/repack/DEBIAN"

# Rename the source tree to the new version and update control/dkms.conf
ORIG_SNAP_SRC=$(find "$SNAP_WORK/repack/usr/src" -maxdepth 1 -name "synosnap-*" -type d | head -1)
[ -z "$ORIG_SNAP_SRC" ] && fail "synosnap source directory not found in unpacked DEB"
SNAP_SRC="$SNAP_WORK/repack/usr/src/synosnap-${SYNOSNAP_VERSION}"
if [ "$ORIG_SNAP_SRC" != "$SNAP_SRC" ]; then
    mv "$ORIG_SNAP_SRC" "$SNAP_SRC"
fi
sed -i "s/^Version: .*/Version: ${SYNOSNAP_VERSION}/" "$SNAP_WORK/repack/DEBIAN/control"
if [ -f "$SNAP_SRC/dkms.conf" ]; then
    sed -i "s/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"${SYNOSNAP_VERSION}\"/" "$SNAP_SRC/dkms.conf"
fi

# Copy all patched synosnap source files
info "  Copying patched feature tests..."
for f in "$PATCHES_DIR/synosnap/configure-tests/feature-tests/"*; do
    dest="$SNAP_SRC/configure-tests/feature-tests/$(basename "$f")"
    sed 's/\r//' "$f" > "$dest"
    chmod --reference="$f" "$dest" 2>/dev/null || true
done

info "  Copying patched source files..."
for f in genconfig.sh includes.h blkdev.h blkdev.c snap_device.h tracer.c \
         bdev_state_handler.c ioctl_handlers.c ftrace_hooking.c system_call_hooking.c \
         mrf.c; do
    sed 's/\r//' "$PATCHES_DIR/synosnap/$f" > "$SNAP_SRC/$f"
    chmod --reference="$PATCHES_DIR/synosnap/$f" "$SNAP_SRC/$f" 2>/dev/null || true
    [[ "$f" == *.sh ]] && chmod +x "$SNAP_SRC/$f"
done

# Disable the Debian 12+ block in postinst that strips AUTOINSTALL="yes" from dkms.conf
# (ABB #11026 — without AUTOINSTALL, DKMS refuses to build the module automatically)
info "  Patching postinst: disabling Debian 12+ DKMS autoinstall removal..."
sed -i "s|sed -i '/AUTOINSTALL=\"yes\"/d' /usr/src/|# sed -i '/AUTOINSTALL=\"yes\"/d' /usr/src/|" \
    "$SNAP_WORK/repack/DEBIAN/postinst"

# Build the patched synosnap DEB
PATCHED_SYNOSNAP_DEB="$WORKDIR/synosnap-${SYNOSNAP_VERSION}.deb"
dpkg-deb --root-owner-group -b "$SNAP_WORK/repack" "$PATCHED_SYNOSNAP_DEB"
ok "Built patched synosnap DEB"

# --- Step 3: Repackage agent DEB with updated version ---
info "Repacking agent DEB with version ${AGENT_VERSION}..."

AGENT_WORK="$WORKDIR/agent_repack"
mkdir -p "$AGENT_WORK"

dpkg-deb -R "$ORIG_AGENT_DEB" "$AGENT_WORK/repack"
chmod 0755 "$AGENT_WORK/repack/DEBIAN"

# Update version in control file
sed -i "s/^Version: .*/Version: ${AGENT_VERSION}/" "$AGENT_WORK/repack/DEBIAN/control"

# Update DRIVER_INFO version tag
DRIVER_INFO="$AGENT_WORK/repack/opt/Synology/ActiveBackupforBusiness/data/DRIVER_INFO"
if [ -f "$DRIVER_INFO" ]; then
    sed -i "s/\"version\": \"${SYNOSNAP_VERSION}\"/\"version\": \"${SYNOSNAP_VERSION}-${AGENT_BUILD_TAG}\"/" "$DRIVER_INFO"
fi

# Binary-patch build number in abb-cli and service-ctrl (4967 → 4969)
# The binaries store the build number as a null-terminated 4-byte string "4967\0".
# We replace it with "4969" (same length) so `abb-cli -v` shows 3.1.0-4969.
info "  Patching build number in binaries (4967 → 4969)..."
for bin in \
    "$AGENT_WORK/repack/bin/abb-cli" \
    "$AGENT_WORK/repack/opt/Synology/ActiveBackupforBusiness/bin/service-ctrl" \
    "$AGENT_WORK/repack/opt/Synology/ActiveBackupforBusiness/bin/synology-backupd"; do
    if [ -f "$bin" ]; then
        perl -pi -e 's/build\x004967\x00/build\x004969\x00/g' "$bin"
        ok "  Patched $(basename "$bin")"
    fi
done

# Build the patched agent DEB
PATCHED_AGENT_DEB="$WORKDIR/Synology Active Backup for Business Agent-${AGENT_VERSION}.deb"
dpkg-deb --root-owner-group -b "$AGENT_WORK/repack" "$PATCHED_AGENT_DEB"
ok "Built patched agent DEB (version ${AGENT_VERSION})"

# --- Step 4: Build the install.run self-extracting archive ---
info "Building install.run..."

PAYLOAD_DIR="$WORKDIR/payload"
mkdir -p "$PAYLOAD_DIR"

# Copy installer scripts from original
cp "$EXTRACTED/install.sh" "$PAYLOAD_DIR/"
cp "$EXTRACTED/dkms_common.postinst" "$PAYLOAD_DIR/"

# Copy patched variables.sh (strip CRLF in case of Windows checkout)
sed 's/\r//' "$PATCHES_DIR/variables.sh" > "$PAYLOAD_DIR/variables.sh"

# Copy patched DEBs (with the names the installer expects from variables.sh)
cp "$PATCHED_SYNOSNAP_DEB" "$PAYLOAD_DIR/synosnap-${SYNOSNAP_VERSION}.deb"
cp "$PATCHED_AGENT_DEB" "$PAYLOAD_DIR/Synology Active Backup for Business Agent-${AGENT_VERSION}.deb"

OUTPUT_FILE="$OUTPUT_DIR/install.run"

# Try makeself first, fall back to manual tar+shell approach
if command -v makeself &>/dev/null; then
    info "Using makeself..."
    makeself --gzip "$PAYLOAD_DIR" "$OUTPUT_FILE" \
        "Synology Active Backup for Business Agent ${AGENT_VERSION}" \
        ./install.sh
else
    info "makeself not found, building archive manually..."
    PAYLOAD_TAR="$WORKDIR/payload.tar.gz"
    (cd "$PAYLOAD_DIR" && tar czf "$PAYLOAD_TAR" .)

    cat > "$OUTPUT_FILE" << 'HEADER'
#!/bin/bash
# Synology Active Backup for Business Agent - Patched installer
# Kernel 6.12-6.18 support (4969 build)
echo "Synology Active Backup for Business Agent"
echo "Extracting..."

TMPDIR=$(mktemp -d)
ARCHIVE=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' "$0")

tail -n+${ARCHIVE} "$0" | tar xzf - -C "$TMPDIR"
if [ $? -ne 0 ]; then
    echo "Error extracting archive"
    exit 1
fi

echo "Running installer..."
cd "$TMPDIR"
bash ./install.sh "$@"
RET=$?
cd /
rm -rf "$TMPDIR"
exit $RET

__ARCHIVE_BELOW__
HEADER

    cat "$PAYLOAD_TAR" >> "$OUTPUT_FILE"
    chmod +x "$OUTPUT_FILE"
fi

ok "Created: $OUTPUT_FILE"
ls -lh "$OUTPUT_FILE"

echo ""
info "Done! Deploy with:  sudo bash install.run"
