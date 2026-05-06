# Arch Linux Installer Design

**Date:** 2026-05-06  
**Status:** Approved

## Goal

Produce `install-arch.run` — a self-extracting installer for Synology Active Backup for Business Agent on Arch Linux, matching the user experience of the existing `install.run` for Debian/Ubuntu. The same script handles both install and uninstall.

## Repository Layout

```
build-tools-arch/
  build-arch.sh          # builds install-arch.run from the patched DEBs
  install-arch.sh        # bundled into install-arch.run; handles install + uninstall

build/
  install.run            # existing Debian/Ubuntu installer (unchanged)
  install-arch.run       # new output: Arch Linux installer
```

The existing `build-tools/` and `build/install.run` are not modified.

## build-arch.sh

Mirrors `build-tools/build.sh`. Accepts the same input (original `source/install.run` or an already-extracted directory). Reuses the patched DEBs by either:
- Running `build-tools/build.sh` first to produce the patched DEBs, or
- Extracting them from the already-built `build/install.run`

Packs `install-arch.sh` + both patched DEBs into `build/install-arch.run` using the same manual `tar`+shell-header format used by `build-tools/build.sh`.

## install-arch.sh

Single script bundled inside `install-arch.run`. Accepts one optional argument: `uninstall`.

### Install path (default, no argument)

1. **Preflight checks**
   - Confirm `x86_64` architecture
   - Confirm `/etc/arch-release` exists (Arch Linux)
   - Confirm running as root

2. **Dependencies** via `pacman -S --needed --noconfirm dkms linux-headers base-devel`
   - Aborts with a clear message if `pacman` is not found

3. **Extract DEBs manually** (no `dpkg` needed)
   - Uses `ar x` + `tar xf data.tar.*` on both DEBs into a temp directory

4. **Install synosnap (kernel module)**
   - Copy source tree to `/usr/src/synosnap-<VERSION>/`
   - Register with DKMS: `dkms add synosnap/<VERSION>`
   - Build and install: `dkms install synosnap/<VERSION>`
   - Install `/etc/modules-load.d/synosnap.conf` (identical to Debian)
   - Install `/lib/systemd/system-shutdown/synosnap.shutdown`
   - Install `/usr/lib/synosnap/libsynosnap.so` (+ `.so.1` symlink)
   - Install `/bin/sbdctl`
   - Add mkinitcpio hook at `/etc/initcpio/hooks/synosnap` and `/etc/initcpio/install/synosnap`
   - Run `mkinitcpio -P` to rebuild all presets
   - **Skip** Debian-specific files: `/etc/apt/`, `/etc/kernel/postinst.d/`, `/usr/share/initramfs-tools/`

5. **Install agent**
   - Copy `/opt/Synology/ActiveBackupforBusiness/` tree as-is (bundles its own libs)
   - Copy `/bin/abb-cli`
   - Install systemd service file to `/etc/systemd/system/`
   - `systemctl daemon-reload && systemctl enable --now synology-active-backup-business-linux-service`

6. **Write manifest** to `/opt/synosnap/arch-manifest.txt`
   - One absolute path per line for every installed file and directory (deepest first for clean removal)

### Uninstall path (`install-arch.sh uninstall`)

1. `systemctl stop synology-active-backup-business-linux-service` (ignore failure if not running)
2. `systemctl disable synology-active-backup-business-linux-service`
3. `dkms remove synosnap/<VERSION> --all`
4. Remove `/usr/src/synosnap-<VERSION>/`
5. `mkinitcpio -P` to rebuild initramfs without synosnap
6. Remove every path listed in `/opt/synosnap/arch-manifest.txt`
7. Delete the manifest itself
8. **Fallback**: if manifest is missing, remove a hardcoded list of known install paths

## Compatibility notes

- The agent binaries (`synology-backupd`, `abb-cli`, `service-ctrl`) are ELF 64-bit, dynamically linked, but ship all non-standard dependencies (ICU 56, liblvm2app, libdevmapper, etc.) in `/opt/Synology/ActiveBackupforBusiness/lib/`. External runtime deps are limited to the standard C/C++ runtime and `libselinux` — both always present on Arch.
- The systemd service file from the Debian package installs without modification on Arch.
- DKMS behavior on Arch is identical to Debian for the purposes of this module.
- `linux-headers` on Arch matches the running kernel by default; users on non-stock kernels (e.g. `linux-zen`) must install the matching headers manually.

## Out of scope

- Non-x86_64 architectures
- AUR / PKGBUILD packaging (future work)
- Secure Boot signing
