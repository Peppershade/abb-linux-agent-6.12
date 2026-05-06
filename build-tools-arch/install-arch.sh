#!/bin/bash
set -euo pipefail

VERSION_SYNOSNAP="0.12.12"
VERSION_AGENT="3.2.0-5055"
SERVICE_NAME="synology-active-backup-business-linux-service"
MANIFEST="/opt/synosnap/arch-manifest.txt"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SNAP_DEB="$SCRIPT_DIR/synosnap-${VERSION_SYNOSNAP}.deb"
AGENT_DEB="$SCRIPT_DIR/Synology Active Backup for Business Agent-${VERSION_AGENT}.deb"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

preflight() {
    [[ "$(id -u)" -eq 0 ]]         || fail "Must run as root (use sudo)"
    [[ "$(uname -m)" == "x86_64" ]] || fail "Only x86_64 is supported"
    [[ -f /etc/arch-release ]]     || fail "This installer is for Arch Linux only"
    command -v pacman >/dev/null    || fail "pacman not found — is this Arch Linux?"
    command -v ar >/dev/null        || fail "ar not found — install binutils (pacman -S binutils)"
    [[ -f "$SNAP_DEB" ]]            || fail "synosnap DEB not found: $SNAP_DEB"
    [[ -f "$AGENT_DEB" ]]           || fail "Agent DEB not found: $AGENT_DEB"
}

install_deps() {
    info "Installing build dependencies..."
    pacman -S --needed --noconfirm dkms linux-headers base-devel
}

# Usage: extract_deb <deb_file> <dest_dir>
# Extracts the data payload of a .deb into dest_dir using ar + tar (no dpkg needed)
extract_deb() {
    local deb="$1" dest="$2"
    local work
    work=$(mktemp -d)
    (cd "$work" && ar x "$deb")
    local datafile
    datafile=$(find "$work" -maxdepth 1 -name 'data.tar.*' | head -1)
    [[ -n "$datafile" ]] || fail "No data.tar.* in $deb"
    mkdir -p "$dest"
    tar xf "$datafile" -C "$dest"
    rm -rf "$work"
}
