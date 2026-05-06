# Arch Linux Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce `build/install-arch.run` — a self-extracting installer for Synology Active Backup for Business Agent on Arch Linux, with install and uninstall support.

**Architecture:** `build-tools-arch/build-arch.sh` takes the patched `build/install.run` (output of `build-tools/build.sh`), extracts the patched DEBs, and repacks them with `build-tools-arch/install-arch.sh` into `build/install-arch.run` using the same manual tar+shell-header format. `install-arch.sh` handles both install and uninstall and is the only file bundled into the run archive.

**Tech Stack:** Bash, DKMS, mkinitcpio, pacman, systemd, ar, tar

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `build-tools-arch/build-arch.sh` | Create | Builds `build/install-arch.run` from `build/install.run` |
| `build-tools-arch/install-arch.sh` | Create | Installer script bundled inside the run archive |
| `build/install-arch.run` | Generated | Output — not tracked in git |
| `.gitignore` | Modify | Add `build/install-arch.run` |

---

## Task 1: Directory skeleton and .gitignore

**Files:**
- Create: `build-tools-arch/.gitkeep`
- Modify: `.gitignore`

- [ ] **Step 1: Create the directory and placeholder**

```bash
mkdir -p build-tools-arch
touch build-tools-arch/.gitkeep
```

- [ ] **Step 2: Add install-arch.run to .gitignore**

Open `.gitignore` and add this line after the existing `build/install.run` entry (or at the end):

```
build/install-arch.run
```

- [ ] **Step 3: Commit**

```bash
git add build-tools-arch/.gitkeep .gitignore
git commit -m "chore: scaffold build-tools-arch directory"
```

Expected: commit succeeds, `build-tools-arch/` visible in repo.

---

## Task 2: Write `install-arch.sh` — skeleton, preflight, deps, DEB extractor

**Files:**
- Create: `build-tools-arch/install-arch.sh`

- [ ] **Step 1: Create the file with header, constants, helpers, and preflight**

`build-tools-arch/install-arch.sh`:

```bash
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
    [[ "$(id -u)" -eq 0 ]]        || fail "Must run as root (use sudo)"
    [[ "$(uname -m)" == "x86_64" ]] || fail "Only x86_64 is supported"
    [[ -f /etc/arch-release ]]    || fail "This installer is for Arch Linux only"
    command -v pacman >/dev/null   || fail "pacman not found — is this Arch Linux?"
    command -v ar >/dev/null       || fail "ar not found — install binutils (pacman -S binutils)"
    [[ -f "$SNAP_DEB" ]]           || fail "synosnap DEB not found: $SNAP_DEB"
    [[ -f "$AGENT_DEB" ]]          || fail "Agent DEB not found: $AGENT_DEB"
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
```

- [ ] **Step 2: Make the file executable**

```bash
chmod +x build-tools-arch/install-arch.sh
```

- [ ] **Step 3: Verify the shell parses cleanly**

```bash
bash -n build-tools-arch/install-arch.sh
```

Expected: no output (no syntax errors).

- [ ] **Step 4: Commit**

```bash
git add build-tools-arch/install-arch.sh
git commit -m "feat(arch): install-arch.sh skeleton — preflight, deps, DEB extractor"
```

---

## Task 3: Add `install_synosnap()` to install-arch.sh

**Files:**
- Modify: `build-tools-arch/install-arch.sh`

This function: extracts the synosnap DEB, installs the DKMS source, installs runtime files, writes mkinitcpio hooks, registers and builds the DKMS module, and rebuilds the initramfs.

- [ ] **Step 1: Append `install_synosnap()` to the file**

Add the following after the `extract_deb` function:

```bash
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
```

- [ ] **Step 2: Verify syntax**

```bash
bash -n build-tools-arch/install-arch.sh
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add build-tools-arch/install-arch.sh
git commit -m "feat(arch): install_synosnap — DKMS install + mkinitcpio hooks"
```

---

## Task 4: Add `install_agent()`, manifest, and `do_install()` to install-arch.sh

**Files:**
- Modify: `build-tools-arch/install-arch.sh`

- [ ] **Step 1: Append `install_agent()`, `write_manifest()`, and `do_install()`**

```bash
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
```

- [ ] **Step 2: Verify syntax**

```bash
bash -n build-tools-arch/install-arch.sh
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add build-tools-arch/install-arch.sh
git commit -m "feat(arch): install_agent, manifest, do_install"
```

---

## Task 5: Add `do_uninstall()` and main entrypoint to install-arch.sh

**Files:**
- Modify: `build-tools-arch/install-arch.sh`

- [ ] **Step 1: Append `do_uninstall()` and the main entrypoint**

```bash
do_uninstall() {
    [[ "$(id -u)" -eq 0 ]] || fail "Must run as root (use sudo)"

    info "Stopping and disabling service..."
    systemctl stop "$SERVICE_NAME"  2>/dev/null || true
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
```

- [ ] **Step 2: Verify syntax**

```bash
bash -n build-tools-arch/install-arch.sh
```

Expected: no output.

- [ ] **Step 3: Do a dry-run preflight test (non-root, expects failure)**

```bash
bash build-tools-arch/install-arch.sh 2>&1 | head -5
```

Expected output contains: `[FAIL] Must run as root`

- [ ] **Step 4: Commit**

```bash
git add build-tools-arch/install-arch.sh
git commit -m "feat(arch): do_uninstall and main entrypoint"
```

---

## Task 6: Write `build-arch.sh`

**Files:**
- Create: `build-tools-arch/build-arch.sh`

This script takes `build/install.run` (the patched Debian installer, output of `build-tools/build.sh`) as input, extracts the two patched DEBs from it, and packs them with `install-arch.sh` into `build/install-arch.run`.

- [ ] **Step 1: Create the file**

`build-tools-arch/build-arch.sh`:

```bash
#!/bin/bash
# build-arch.sh — Build install-arch.run from the patched build/install.run
#
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

[[ -f "$INPUT" ]] || fail "Input not found: $INPUT  (run build-tools/build.sh first)"
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
```

- [ ] **Step 2: Make executable**

```bash
chmod +x build-tools-arch/build-arch.sh
```

- [ ] **Step 3: Verify syntax**

```bash
bash -n build-tools-arch/build-arch.sh
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add build-tools-arch/build-arch.sh
git commit -m "feat(arch): build-arch.sh — pack install-arch.run from patched DEBs"
```

---

## Task 7: Smoke test build-arch.sh (requires Linux/WSL + built install.run)

**Files:** none changed

This task verifies `build-arch.sh` produces a valid archive. Run in WSL or on Linux.

- [ ] **Step 1: Confirm build/install.run exists (build it if not)**

```bash
# If build/install.run doesn't exist yet, build it first:
# wsl.exe bash /mnt/c/Users/schmidt/Documents/GitHub/syno/git/build-tools/build.sh \
#   /mnt/c/Users/schmidt/Documents/GitHub/syno/git/source/install.run
ls -lh build/install.run
```

Expected: file exists, ~40 MB.

- [ ] **Step 2: Run build-arch.sh**

```bash
wsl.exe bash /mnt/c/Users/schmidt/Documents/GitHub/syno/git/build-tools-arch/build-arch.sh
```

Expected output (last lines):
```
[ OK ] Created: .../build/install-arch.run
[INFO] Deploy on Arch Linux with:  sudo bash install-arch.run
[INFO] Uninstall with:             sudo bash install-arch.run uninstall
```

- [ ] **Step 3: Verify the archive is self-consistent**

```bash
wsl.exe bash -c "
  TMPDIR=\$(mktemp -d)
  ARCHIVE=\$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' \
    /mnt/c/Users/schmidt/Documents/GitHub/syno/git/build/install-arch.run)
  tail -n+\${ARCHIVE} \
    /mnt/c/Users/schmidt/Documents/GitHub/syno/git/build/install-arch.run \
    | tar tzf - | sort
  rm -rf \$TMPDIR
"
```

Expected output — exactly these three files:
```
./install-arch.sh
./synosnap-0.12.12.deb
./Synology Active Backup for Business Agent-3.2.0-5055.deb
```

- [ ] **Step 4: Verify preflight rejects non-Arch (in WSL Debian/Ubuntu)**

```bash
wsl.exe bash -c "bash /mnt/c/Users/schmidt/Documents/GitHub/syno/git/build/install-arch.run 2>&1 | head -5"
```

Expected: `[FAIL] This installer is for Arch Linux only`  
(WSL distro is Debian/Ubuntu, not Arch, so `/etc/arch-release` is absent.)

- [ ] **Step 5: Commit smoke test result note and clean up temp files**

```bash
# Remove extract_inspect.sh (temporary investigation file, not needed in repo)
git rm extract_inspect.sh
git commit -m "chore: remove temporary inspection script"
```

---

## Task 8: Update README with Arch Linux section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add Arch Linux section to README.md**

After the existing "## Download" section, add:

```markdown
### Arch Linux

A separate installer is available for Arch Linux:

**[Download install-arch.run](https://github.com/Peppershade/abb-linux-agent/releases/latest)**

```bash
sudo bash install-arch.run
```

To uninstall:

```bash
sudo bash install-arch.run uninstall
```

> **Note:** The installer requires `dkms`, `linux-headers`, and `base-devel`. These are installed automatically via `pacman`.  
> If you use a non-stock kernel (e.g. `linux-zen`, `linux-lts`), install the matching headers first: `pacman -S linux-zen-headers`.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add Arch Linux install instructions to README"
```

---

## Self-Review Notes

- **Spec coverage:**
  - ✅ `build-tools-arch/` directory
  - ✅ `build-arch.sh` — builds from patched install.run
  - ✅ `install-arch.sh` — pacman deps, ar-based DEB extraction, synosnap DKMS, agent binaries
  - ✅ mkinitcpio hook (replaces initramfs-tools)
  - ✅ manifest file for clean uninstall
  - ✅ `do_uninstall()` — stops service, removes DKMS, rebuilds initramfs, removes files
  - ✅ Debian-specific files (apt hooks, kernel postinst) explicitly skipped
  - ✅ Agent RPATH `../lib` confirmed — bundled libs load automatically, no LD_LIBRARY_PATH needed

- **Types/names consistent across tasks:** `VERSION_SYNOSNAP`, `VERSION_AGENT`, `SERVICE_NAME`, `MANIFEST` defined once in Task 2 header and referenced consistently.

- **Non-stock kernel note:** Users on `linux-zen` etc. need matching headers. Noted in README.
