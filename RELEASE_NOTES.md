## v3.1.0-4969 — Kernel 6.12–6.18 support

Patched build of the Synology Active Backup for Business Agent with Linux kernel 6.12–6.18 support.

### Changes from official 3.1.0-4967
- `synosnap` DKMS kernel module patched for kernel 6.12–6.18 API changes
- Kernel 6.15+: updated `struct mnt_namespace` and `struct mount` definitions
- Kernel 6.17+: `BIO_THROTTLED` → `BIO_QOS_THROTTLED` compat, void `submit_bio` handling
- Build number bumped to 4969

### Tested on
- Debian `6.12.69+deb13-amd64`
- Ubuntu `6.17.0-14-generic` (Ubuntu 25.10)
- Ubuntu `6.18.0-061800-generic` (Ubuntu 25.10)

### Install
```bash
sudo bash install.run
```

### Uninstall
If the DKMS module build fails or you need to remove it cleanly:
```bash
sudo dpkg --remove synosnap 2>/dev/null; sudo dkms remove synosnap/0.11.6 --all 2>/dev/null; true
```

> **WARNING:** This is not an official Synology release. Not affiliated with or supported by Synology Inc. Use at your own risk.
