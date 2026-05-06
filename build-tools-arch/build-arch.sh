#!/bin/bash
# build-arch.sh — Build install-arch.run from the patched build/install.run
# See install-arch.sh for the Arch Linux installer that this script packages.
# Usage:
#   ./build-tools-arch/build-arch.sh [path/to/patched-install.run]
#
# Requires build/install.run to already exist (run build-tools/build.sh first).
# Output: build/install-arch.run
#
# Requirements: tar, gzip. Must run on Linux or WSL.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER_SCRIPT="$SCRIPT_DIR/install-arch.sh"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_DIR/build}"
TEMP_DIR="${TEMP_DIR:-/tmp}"

SYNOSNAP_VERSION="0.12.12"
AGENT_VERSION="3.2.0-5055"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

INPUT="${1:-$REPO_DIR/build/install.run}"

[[ -f "$INPUT" ]]            || fail "Input not found: $INPUT  (run build-tools/build.sh first)"
[[ -f "$INSTALLER_SCRIPT" ]] || fail "install-arch.sh not found: $INSTALLER_SCRIPT"

WORKDIR=$(mktemp -d "$TEMP_DIR/abb-arch-build.XXXXXX")
trap 'rm -rf "$WORKDIR"' EXIT

info "Input:  $INPUT"
info "Output: $OUTPUT_DIR/install-arch.run"
info "Work:   $WORKDIR"

# --- Extract DEBs from input install.run ---
info "Extracting patched DEBs from $INPUT..."
EXTRACTED="$WORKDIR/extracted"
mkdir -p "$EXTRACTED"

# Detect format: our manual format uses __ARCHIVE_BELOW__, makeself uses skip=
if grep -qal '^__ARCHIVE_BELOW__' "$INPUT" 2>/dev/null; then
    ARCHIVE_LINE=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0}' "$INPUT")
    tail -n+"$ARCHIVE_LINE" "$INPUT" | tar xzf - -C "$EXTRACTED"
else
    SKIP=$(grep -a '^skip=' "$INPUT" | head -1 | sed 's/skip=//;s/"//g')
    OFFSET=$(head -n "$SKIP" "$INPUT" | wc -c | tr -d ' ')
    dd if="$INPUT" bs="$OFFSET" skip=1 2>/dev/null | tar xzf - -C "$EXTRACTED"
fi

SNAP_DEB=$(find "$EXTRACTED" -maxdepth 1 -name "synosnap-${SYNOSNAP_VERSION}.deb" | head -1)
AGENT_DEB=$(find "$EXTRACTED" -maxdepth 1 -name "Synology Active Backup for Business Agent-${AGENT_VERSION}.deb" | head -1)

[[ -n "$SNAP_DEB" ]]  || fail "synosnap-${SYNOSNAP_VERSION}.deb not found in $INPUT"
[[ -n "$AGENT_DEB" ]] || fail "Agent DEB ${AGENT_VERSION} not found in $INPUT"

ok "Found synosnap DEB: $(basename "$SNAP_DEB")"
ok "Found agent DEB:    $(basename "$AGENT_DEB")"

# --- Assemble payload ---
info "Assembling payload..."
PAYLOAD="$WORKDIR/payload"
mkdir -p "$PAYLOAD"

cp "$INSTALLER_SCRIPT" "$PAYLOAD/install-arch.sh"
chmod +x "$PAYLOAD/install-arch.sh"
cp "$SNAP_DEB"  "$PAYLOAD/"
cp "$AGENT_DEB" "$PAYLOAD/"

# --- Pack into install-arch.run ---
info "Packing install-arch.run..."
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/install-arch.run"
PAYLOAD_TAR="$WORKDIR/payload.tar.gz"
(cd "$PAYLOAD" && tar czf "$PAYLOAD_TAR" .)

cat > "$OUTPUT_FILE" << 'HEADER'
#!/bin/bash
# Synology Active Backup for Business Agent — Arch Linux installer
# Kernel 6.15-7.0 support (synosnap 0.12.12 / agent 3.2.0-5055)
echo "Synology Active Backup for Business Agent — Arch Linux"
echo "Extracting..."

TMPDIR=$(mktemp -d)
ARCHIVE=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' "$0")

tail -n+"${ARCHIVE}" "$0" | tar xzf - -C "$TMPDIR"
if [ $? -ne 0 ]; then
    echo "Error extracting archive"
    exit 1
fi

echo "Running installer..."
cd "$TMPDIR"
bash ./install-arch.sh "$@"
RET=$?
cd /
rm -rf "$TMPDIR"
exit $RET

__ARCHIVE_BELOW__
HEADER

cat "$PAYLOAD_TAR" >> "$OUTPUT_FILE"
chmod +x "$OUTPUT_FILE"

ok "Created: $OUTPUT_FILE"
ls -lh "$OUTPUT_FILE"
echo ""
info "Deploy on Arch Linux with:  sudo bash install-arch.run"
info "Uninstall with:             sudo bash install-arch.run uninstall"
