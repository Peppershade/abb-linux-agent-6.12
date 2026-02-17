> **WARNING:** This project is **not affiliated with, endorsed by, or supported by Synology Inc.**
> No support is provided — use at your own risk. Tested on `6.12.69+deb13-amd64` only.

# Synology Active Backup for Business Agent - Kernel 6.12 Patches

Patches and build tooling to add **Linux kernel 6.12+** support to the
[Synology Active Backup for Business](https://www.synology.com/en-global/dsm/feature/active_backup_business)
Linux agent (version 3.1.0-4968, based on the official 3.1.0-4967 release).

The official agent ships a DKMS kernel module (`synosnap`) that fails to build
on kernel 6.12 and later due to upstream API changes. This project provides
patched source files and a build script that repackages the official installer
with the fixes applied.

## What is patched

The `synosnap` kernel module source (`/usr/src/synosnap-0.11.6/`) is updated
to handle the following kernel 6.12 API changes:

- `bdev_file_open_by_path()` replaces `bdev_open_by_path()` (new feature test)
- `bdev_freeze()` / `bdev_thaw()` replace `freeze_bdev()` / `thaw_bdev()`
- `BLK_STS_NEXUS` removal — `bdev_test_flag()` feature test added
- `struct file` `fd_file()` accessor in `includes.h`
- `ftrace_hooking.c` updated for 6.12 calling conventions
- `genconfig.sh` rewritten for robust feature detection
- Various other compile fixes across `blkdev.c`, `tracer.c`,
  `bdev_state_handler.c`, `ioctl_handlers.c`, and `system_call_hooking.c`

The agent DEB is also repackaged with the version bumped to `3.1.0-4968` so
the NAS recognizes it as the patched build.

## Prerequisites

- **Linux** (native or WSL) — the build uses `dpkg-deb`, `tar`, and shell tools
- `dpkg-deb` (from `dpkg` package)
- `tar`, `gzip`
- `perl` (for binary version patching)
- `makeself` (optional — the script falls back to a manual archive method)

On Debian/Ubuntu:

```bash
sudo apt install dpkg tar gzip perl
```

## Obtaining the original installer

Download the official **Synology Active Backup for Business Agent 3.1.0-4967**
Linux installer (`.run` file) from the
[Synology Download Center](https://www.synology.com/en-global/support/download).

Navigate to your NAS model, select **Desktop Utilities**, and download
*Active Backup for Business Agent* for Linux (x64 / deb).

## Building

```bash
bash build-tools/build.sh /path/to/original-install.run
```

This will:

1. Extract the official installer payload
2. Unpack the `synosnap` DEB, replace source files with patched versions
3. Repack the agent DEB with the updated version number
4. Produce a new `install.run` in the current directory

## Verifying the build

```bash
bash verify_build.sh
```

This extracts the generated `install.run` and checks that patched files,
version numbers, and binary patches are all present.

You can optionally pass the path to the `.run` file:

```bash
bash verify_build.sh /path/to/install.run
```

If omitted, it defaults to `install.run` in the same directory as the script.

## Installing

Copy the generated `install.run` to the target Linux machine and run:

```bash
sudo bash install.run
```

The installer will set up the agent and build the `synosnap` kernel module via
DKMS, just like the official installer.

## Uninstall

If the DKMS module build fails or you need to remove it cleanly:

```bash
sudo dpkg --remove synosnap 2>/dev/null; sudo dkms remove synosnap/0.11.6 --all 2>/dev/null; true
```

## Repository layout

```
build-tools/
  build.sh                       # Main build script
  patches/
    variables.sh                 # Installer variable overrides (version 4968)
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

**Tested and verified working** on Debian `6.12.69+deb13-amd64`. Other kernel
6.12+ versions may work but have not been explicitly tested.

## License

The patched source files are derived from Synology's original `synosnap` module
(based on [dattobd](https://github.com/datto/dattobd)). The original code is
licensed under the GPL v2. Patches in this repository are provided under the
same license.
