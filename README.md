> **WARNING:** This project is **not affiliated with, endorsed by, or supported by Synology Inc.**
> No support is provided — use at your own risk.

# Synology Active Backup for Business Agent — Kernel 6.12–6.18 Patches

Synology has not updated the Active Backup for Business Linux agent since
kernel 6.8. Their `synosnap` DKMS module fails to compile on 6.12 and later
due to upstream kernel API changes — leaving users on modern distributions
(Debian 13, Ubuntu 24.04 HWE, Ubuntu 25.04/25.10) unable to back up their
machines. Rather than waiting indefinitely, this project patches the module
source and repackages the installer so it works again.

The version is bumped only slightly (`3.1.0-4969` over the official `3.1.0-4967`),
so when Synology eventually releases an official update with proper kernel
support, ABB will automatically install their version over this one.

## Download

Pre-built installer ready to deploy:

**[Download install.run](https://github.com/Peppershade/abb-linux-agent-6.12/releases/latest)**

```bash
sudo bash install.run
```

The installer sets up the agent and builds the `synosnap` kernel module via
DKMS, just like the official installer.

### Verified kernel versions

| Kernel | Distribution | Status |
|--------|-------------|--------|
| `6.12.69+deb13-amd64` | Debian 13 | Verified |
| `6.17.0-14-generic` | Ubuntu 25.10 | Verified |
| `6.18.0-061800-generic` | Ubuntu 25.10 | Verified |

Running a kernel not listed here? Please
[open an issue](https://github.com/Peppershade/abb-linux-agent-6.12/issues)
to report whether it works — this helps others and helps us track compatibility.

## Uninstall

If the DKMS module build fails or you need to remove it cleanly:

```bash
sudo dpkg --remove synosnap 2>/dev/null; sudo dkms remove synosnap/0.11.7 --all 2>/dev/null; true
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

Download the official **Synology Active Backup for Business Agent 3.1.0-4967**
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

### Verifying the build

```bash
bash verify_build.sh [/path/to/install.run]
```

Checks that patched files, version numbers, and binary patches are all present.
If no path is given, it defaults to `install.run` in the same directory as the script.

---

## What is patched

The `synosnap` kernel module source (`/usr/src/synosnap-0.11.7/`) is updated
to handle kernel API changes from **6.12 through 6.18**:

### Kernel 6.12
- `bdev_file_open_by_path()` replaces `bdev_open_by_path()` (new feature test)
- `bdev_freeze()` / `bdev_thaw()` replace `freeze_bdev()` / `thaw_bdev()`
- `BLK_STS_NEXUS` removal — `bdev_test_flag()` feature test added
- `struct file` `fd_file()` accessor in `includes.h`
- `ftrace_hooking.c` updated for 6.12 calling conventions
- `genconfig.sh` rewritten for robust feature detection (`ccflags-y`, per-test
  temp directories for kbuild compatibility)
- Various other compile fixes across `blkdev.c`, `tracer.c`,
  `bdev_state_handler.c`, `ioctl_handlers.c`, and `system_call_hooking.c`

### Kernel 6.15+
- `struct mnt_namespace` layout changes (`seq` → `seq_origin`, `mounts` wrapped
  in anonymous struct, `mnt_ns_tree_node`/`mnt_ns_list`/`ns_lock` removed,
  fsnotify fields added)
- `struct mount` layout changes (`mnt_instance` removed, `mnt_node` in top union,
  slave lists changed from `list_head` to `hlist_head`, new fields `mnt_t_flags`,
  `mnt_id_unique`, `overmount`)

### Kernel 6.17+
- `BIO_THROTTLED` renamed to `BIO_QOS_THROTTLED` — compat define added
- `submit_bio()` / `submit_bio_noacct()` return type changed to `void` —
  `mrf.c` patched with conditional return handling
- New feature tests: `bio_qos_throttled.c`, `submit_bio_noacct_void.c`
- `EXTRA_CFLAGS` dropped by kbuild — feature test system updated to `ccflags-y`

### Installer / packaging fixes
- **Debian 12+ DKMS autoinstall** — the original `postinst` stripped
  `AUTOINSTALL="yes"` from `dkms.conf` on Debian 12+, causing DKMS to refuse
  to build the module. That block is now disabled during repackaging.
- **Unloaded kernel fallback** — `genconfig.sh` previously hard-failed when
  building for a kernel not currently running (e.g. after a kernel upgrade).
  It now falls back to `/proc/kallsyms` with a warning instead of aborting.
- **synosnap version bump to 0.11.7** — forces reinstallation of the patched
  module on machines that already had `0.11.6` installed.

## Repository layout

```
build-tools/
  build.sh                       # Main build script
  patches/
    variables.sh                 # Installer variable overrides (version 4969)
    synosnap/                    # Patched kernel module sources
      configure-tests/
        feature-tests/           # Kernel feature detection tests
verify_build.sh                  # Post-build verification
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
  Debian 12+ DKMS autoinstall fix ([#2](https://github.com/Peppershade/abb-linux-agent-6.12/pull/2))

## License

The patched source files are derived from Synology's original `synosnap` module
(based on [dattobd](https://github.com/datto/dattobd)). The original code is
licensed under the GPL v2. Patches in this repository are provided under the
same license.
