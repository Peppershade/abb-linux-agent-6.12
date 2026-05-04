> **WARNING:** This project is **not affiliated with, endorsed by, or supported by Synology Inc.**
> No support is provided — use at your own risk.

# Synology Active Backup for Business Agent — Kernel 6.15–7.0 Patches

[![DKMS module build](https://github.com/Peppershade/abb-linux-agent/actions/workflows/test-dkms.yml/badge.svg)](https://github.com/Peppershade/abb-linux-agent/actions/workflows/test-dkms.yml)

Synology's `3.2.0-5053` release officially added support up to kernel 6.14.
Their `synosnap` DKMS module still fails to compile on 6.15 and later due to
further upstream kernel API changes — leaving users on the latest distributions
(Ubuntu 25.04/25.10) unable to back up their machines. This project patches the
module source and repackages the installer so it works again.

The version is bumped only slightly (`3.2.0-5055` over the official `3.2.0-5053`),
so when Synology eventually releases an official update with proper kernel
support, ABB will automatically install their version over this one.

## Download

Pre-built installer ready to deploy:

**[Download install.run](https://github.com/Peppershade/abb-linux-agent/releases/latest)**

```bash
sudo bash install.run
```

The installer sets up the agent and builds the `synosnap` kernel module via
DKMS, just like the official installer.

### Verified kernel versions

| Kernel | Distribution | Status |
|--------|-------------|--------|
| `6.12.74+deb13+1-amd64` | Debian 13 | Verified |
| `6.14.0-061400-generic` | Ubuntu mainline | CI Tested |
| `6.15.0-061500-generic` | Ubuntu mainline | CI Tested |
| `6.17.0-061700-generic` | Ubuntu mainline | CI Tested |
| `6.17.0-19-generic` | Ubuntu 25.10 | Verified |
| `6.18.0-061800-generic` | Ubuntu 25.10 | CI Tested |
| `6.19.0-061900-generic` | Ubuntu mainline | CI Tested |
| `6.19.10-061910-generic` | Ubuntu 25.10 | Verified |
| `7.0.0-070000-generic` | Ubuntu 25.10 | Verified |
| `7.0.0-14-generic` | Kubuntu 26.04 LTS | Verified |

**Status legend:**
- **Verified** — full install tested on real hardware; agent connected and backed up successfully
- **CI Tested** — `synosnap` module compiled successfully against mainline kernel headers in GitHub Actions; not yet confirmed with a live install

> **Note:** Kernels 6.12–6.13 are officially supported by Synology's `3.2.0-5053` release and are not tested here.

## Secure Boot

This installer is not compatible with Secure Boot. The `synosnap` DKMS module
is not signed with a trusted key, so the kernel will refuse to load it on
systems with Secure Boot enabled.

**You must disable Secure Boot** in your firmware (UEFI) settings before
installing, or enroll your own MOK key and sign the module manually after
building.

If you install with Secure Boot active, the module will build successfully but
fail to load, and backups will not run.

Running a kernel not listed here? Please
[open an issue](https://github.com/Peppershade/abb-linux-agent/issues)
to report whether it works — this helps others and helps us track compatibility.

## Uninstall

If the DKMS module build fails or you need to remove it cleanly:

```bash
sudo dpkg --remove synosnap 2>/dev/null; sudo dkms remove synosnap/0.12.12 --all 2>/dev/null; sudo dkms remove synosnap/0.12.11 --all 2>/dev/null; true
```

---

## Build it yourself

If you prefer to inspect the source and build from scratch rather than
trusting a pre-built binary:

### Prerequisites

- **Linux** (native or WSL) — the build uses `dpkg-deb`, `tar`, and shell tools
- `dpkg-deb` (from `dpkg` package)
- `tar`, `gzip`
- `perl` (for binary version patching)
- `makeself` (optional — the script falls back to a manual archive method)

On Debian/Ubuntu:

```bash
sudo apt install dpkg tar gzip perl
```

### Obtaining the original installer

Download the official **Synology Active Backup for Business Agent 3.2.0-5053**
Linux installer (`.run` file) from the
[Synology Download Center](https://www.synology.com/en-global/support/download).

Navigate to your NAS model, select **Desktop Utilities**, and download
*Active Backup for Business Agent* for Linux (x64 / deb).

### Building

```bash
bash build-tools/build.sh /path/to/original-install.run
```

This will:

1. Extract the official installer payload
2. Unpack the `synosnap` DEB, replace source files with patched versions
3. Repack the agent DEB with the updated version number
4. Produce a new `install.run` in the current directory

---

## What is patched

The `synosnap` kernel module source (`/usr/src/synosnap-0.12.12/`) is based on
Synology's `0.12.10` (from `3.2.0-5053`) and patched to handle kernel API
changes from **6.15 through 7.0**:

### Kernel 6.17+
- **Data corruption fix** — `synosnap` was marking bios with bit 28 of
  `bio->bi_opf` as a passthrough flag. Kernel 6.17 reclaimed bit 28 as
  `REQ_P2PDMA`, causing NVMe to return `BLK_STS_INVAL` on every tracked write,
  which made ext4 fail unwritten→written extent conversions and silently corrupt
  files. Fixed by replacing the bit-flag with a `current == sd_mrf_thread` check
  (the re-entry from `blk_mq_submit_bio` always runs on that thread synchronously).
- `freeze_super()` / `thaw_super()` gained a third `owner` argument —
  `freeze_super_3.c` feature test added, `main.c` updated with new call path

### Kernel log noise reduction
- **Spurious ioctl errors suppressed** — the agent sends `IOCTL_TRANSITION_INC`
  on devices already in incremental mode during normal backup completion; the
  driver now returns success (idempotent) instead of `-EINVAL`, eliminating the
  repeated `device specified is not in active snapshot mode` / `error during
  transition to incremental ioctl handler` messages.  Similarly, `IOCTL_DESTROY`
  and the elastio-snap info ioctl no longer log errors when the device is already
  gone (`-ENOENT`) — these are normal cleanup calls on agent restart. A copy-paste
  bug in the elastio-snap info error message (which claimed to be the reconfigure
  handler) is also fixed.

### Installer / packaging fixes
- **Debian 12+ DKMS autoinstall** — the original `postinst` stripped
  `AUTOINSTALL="yes"` from `dkms.conf` on Debian 12+, causing DKMS to refuse
  to build the module. That block is now disabled during repackaging.
- **Unloaded kernel fallback** — `genconfig.sh` hard-failed when building for
  a kernel not currently running (e.g. after a kernel upgrade or in CI).
  It now falls back to `/proc/kallsyms` with a warning instead of aborting.
- **synosnap version bump to 0.12.12** — forces reinstallation of the patched
  module on machines that already had `0.12.11` or earlier installed.

## Repository layout

```
build-tools/
  build.sh                       # Main build script
  patches/
    variables.sh                 # Installer variable overrides (version 5055)
    synosnap/                    # Patched kernel module sources
      configure-tests/
        feature-tests/           # Kernel feature detection tests
source/
  install.run                    # Place official 3.2.0-5053 installer here (gitignored)
```

## Disclaimer

This project is **not affiliated with, endorsed by, or supported by Synology Inc.**
It is an independent, community-driven effort to extend kernel compatibility for
the Active Backup for Business Agent.

**No support is provided.** This is a best-effort project — help may be offered
through issues, but there are no guarantees of response time or resolution.
Use at your own risk.

## Contributors

- [Árpád Szász](https://github.com/arpadszasz) — TEMP_DIR support, extraction fix,
  Debian 12+ DKMS autoinstall fix ([#2](https://github.com/Peppershade/abb-linux-agent/pull/2))
- [noidvan](https://github.com/noidvan) — fix data corruption on kernel 6.17+ (REQ_P2PDMA bit 28
  clash in `bio->bi_opf`) ([#14](https://github.com/Peppershade/abb-linux-agent/pull/14))

## License

The patched source files are derived from Synology's `synosnap` kernel module,
which is based on [elastio-snap](https://github.com/Axcient/elastio-snap)
(maintained by Axcient; originally [dattobd](https://github.com/datto/dattobd) by Datto Inc.).
The original code is licensed under the GPL v2. Patches in this repository are
provided under the same license.
