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

install_synosnap() {
    local snap_root
    snap_root=$(mktemp -d)
    trap 'rm -rf "$snap_root"' RETURN

    info "Extracting synosnap DEB..."
    extract_deb "$SNAP_DEB" "$snap_root"

    info "Installing DKMS source tree..."
    cp -r "$snap_root/usr/src/synosnap-${VERSION_SYNOSNAP}" "/usr/src/"

    info "Installing synosnap runtime files..."
    install -Dm644 "$snap_root/etc/modules-load.d/synosnap.conf" \
        "/etc/modules-load.d/synosnap.conf"
    install -Dm755 "$snap_root/lib/systemd/system-shutdown/synosnap.shutdown" \
        "/lib/systemd/system-shutdown/synosnap.shutdown"
    install -Dm755 "$snap_root/bin/sbdctl" "/bin/sbdctl"
    install -Dm755 "$snap_root/usr/lib/synosnap/libsynosnap.so" \
        "/usr/lib/synosnap/libsynosnap.so"
    ln -sf libsynosnap.so "/usr/lib/synosnap/libsynosnap.so.1"
    install -Dm755 "$snap_root/opt/synosnap/dla/reload" "/opt/synosnap/dla/reload"
    install -Dm644 "$snap_root/opt/synosnap/openssl.conf" "/opt/synosnap/openssl.conf"

    info "Writing mkinitcpio hooks..."
    install -dm755 /etc/initcpio/hooks /etc/initcpio/install
    install -dm755 /etc/mkinitcpio.conf.d

    # Runtime hook — runs inside initramfs at early boot; loads module and restores CBT data
    cat > /etc/initcpio/hooks/synosnap << 'RUNTIMEHOOK'
#!/usr/bin/ash
run_hook() {
    modprobe synosnap 2>/dev/null || echo "synosnap: modprobe failed" >/dev/kmsg

    rbd="${root#block:}"
    [ -n "$rbd" ] || return 0

    case "$rbd" in
        LABEL=*)     rbd="/dev/disk/by-label/${rbd#LABEL=}" ;;
        UUID=*)      rbd="/dev/disk/by-uuid/${rbd#UUID=}" ;;
        PARTLABEL=*) rbd="/dev/disk/by-partlabel/${rbd#PARTLABEL=}" ;;
        PARTUUID=*)  rbd="/dev/disk/by-partuuid/${rbd#PARTUUID=}" ;;
    esac

    [ -b "$rbd" ] || udevadm settle

    [ -n "$ROOTFSTYPE" ] || ROOTFSTYPE=$(blkid -s TYPE -o value "$rbd")

    blockdev --setro "$rbd"
    if mount -t "$ROOTFSTYPE" -o ro "$rbd" /etc/synosnap/dla/mnt 2>/dev/null; then
        udevadm settle
        [ -x /sbin/synosnap_reload ] && /sbin/synosnap_reload
        umount -f /etc/synosnap/dla/mnt
    else
        echo "synosnap: cannot mount rootfs for CBT reload" >/dev/kmsg
    fi
    blockdev --setrw "$rbd"
}
RUNTIMEHOOK
    chmod 755 /etc/initcpio/hooks/synosnap

    # Install hook — runs at mkinitcpio build time; adds binaries and module to initramfs
    cat > /etc/initcpio/install/synosnap << 'INSTALLHOOK'
#!/bin/bash
build() {
    add_module synosnap
    add_binary /bin/sbdctl
    [[ -x /opt/synosnap/dla/reload ]] && add_binary /opt/synosnap/dla/reload /sbin/synosnap_reload
    add_binary blkid
    add_binary blockdev
    add_dir /etc/synosnap/dla/mnt
}
help() {
    echo "Loads synosnap kernel module and restores CBT tracking data at early boot"
}
INSTALLHOOK
    chmod 755 /etc/initcpio/install/synosnap

    # Drop-in config adds synosnap to HOOKS without editing mkinitcpio.conf
    echo 'HOOKS+=(synosnap)' > /etc/mkinitcpio.conf.d/synosnap.conf

    info "Registering with DKMS..."
    dkms add "synosnap/${VERSION_SYNOSNAP}"
    dkms install "synosnap/${VERSION_SYNOSNAP}" || \
        fail "DKMS build failed — check 'dkms status' and ensure linux-headers are installed"

    info "Rebuilding initramfs..."
    mkinitcpio -P

    ok "synosnap ${VERSION_SYNOSNAP} installed"
}

install_agent() {
    local agent_root
    agent_root=$(mktemp -d)
    trap 'rm -rf "$agent_root"' RETURN

    info "Extracting agent DEB..."
    extract_deb "$AGENT_DEB" "$agent_root"

    info "Installing agent binaries and libraries..."
    cp -r "$agent_root/opt/Synology" /opt/
    install -Dm755 "$agent_root/bin/abb-cli" /bin/abb-cli

    info "Installing systemd service..."
    install -Dm644 \
        "$agent_root/etc/systemd/system/${SERVICE_NAME}.service" \
        "/etc/systemd/system/${SERVICE_NAME}.service"

    if [[ -f "$agent_root/lib/systemd/system-sleep/notify-abb.sh" ]]; then
        install -Dm755 "$agent_root/lib/systemd/system-sleep/notify-abb.sh" \
            "/lib/systemd/system-sleep/notify-abb.sh"
    fi

    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"

    ok "Agent ${VERSION_AGENT} installed and started"
}

write_manifest() {
    mkdir -p /opt/synosnap
    {
        # Generated from installed paths — used by uninstall
        find "/usr/src/synosnap-${VERSION_SYNOSNAP}" -depth
        echo "/etc/modules-load.d/synosnap.conf"
        echo "/lib/systemd/system-shutdown/synosnap.shutdown"
        echo "/bin/sbdctl"
        echo "/usr/lib/synosnap/libsynosnap.so.1"
        echo "/usr/lib/synosnap/libsynosnap.so"
        echo "/usr/lib/synosnap"
        echo "/opt/synosnap/dla/reload"
        echo "/opt/synosnap/dla"
        echo "/opt/synosnap/openssl.conf"
        echo "/etc/initcpio/hooks/synosnap"
        echo "/etc/initcpio/install/synosnap"
        echo "/etc/mkinitcpio.conf.d/synosnap.conf"
        find /opt/Synology -depth
        echo "/bin/abb-cli"
        echo "/etc/systemd/system/${SERVICE_NAME}.service"
        [[ -f /lib/systemd/system-sleep/notify-abb.sh ]] && \
            echo "/lib/systemd/system-sleep/notify-abb.sh"
    } > "$MANIFEST"
    ok "Manifest written to $MANIFEST"
}

do_install() {
    preflight
    install_deps
    install_synosnap
    install_agent
    write_manifest
    echo ""
    ok "Installation complete."
    echo " * Run 'abb-cli -c' to connect to your Synology NAS."
    echo " * Run 'abb-cli -h' for all commands."
    echo " * To uninstall: sudo bash install-arch.sh uninstall"
}

do_uninstall() {
    [[ "$(id -u)" -eq 0 ]] || fail "Must run as root (use sudo)"

    info "Stopping and disabling service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true

    info "Removing DKMS module..."
    if dkms status | grep -q "synosnap"; then
        dkms remove "synosnap/${VERSION_SYNOSNAP}" --all || true
    fi
    rm -rf "/usr/src/synosnap-${VERSION_SYNOSNAP}"

    info "Rebuilding initramfs without synosnap..."
    rm -f /etc/mkinitcpio.conf.d/synosnap.conf
    mkinitcpio -P

    if [[ -f "$MANIFEST" ]]; then
        info "Removing installed files from manifest..."
        while IFS= read -r path; do
            if [[ -f "$path" || -L "$path" ]]; then
                rm -f "$path"
            elif [[ -d "$path" ]]; then
                rmdir --ignore-fail-on-non-empty "$path" 2>/dev/null || true
            fi
        done < "$MANIFEST"
        rm -f "$MANIFEST"
    else
        info "Manifest not found — removing known paths..."
        rm -f /etc/modules-load.d/synosnap.conf
        rm -f /lib/systemd/system-shutdown/synosnap.shutdown
        rm -f /bin/sbdctl
        rm -f /usr/lib/synosnap/libsynosnap.so.1
        rm -f /usr/lib/synosnap/libsynosnap.so
        rmdir --ignore-fail-on-non-empty /usr/lib/synosnap 2>/dev/null || true
        rm -rf /opt/synosnap
        rm -f /etc/initcpio/hooks/synosnap
        rm -f /etc/initcpio/install/synosnap
        rm -f /bin/abb-cli
        rm -rf /opt/Synology
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        rm -f /lib/systemd/system-sleep/notify-abb.sh
    fi

    systemctl daemon-reload
    ok "Uninstall complete."
}

# --- Entrypoint ---
case "${1:-install}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    *)
        echo "Usage: $0 [install|uninstall]"
        exit 1
        ;;
esac
