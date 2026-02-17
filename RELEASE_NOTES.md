## v3.1.0-4968 — Kernel 6.12 support

Patched build of the Synology Active Backup for Business Agent with Linux kernel 6.12+ support.

### Changes from official 3.1.0-4967
- `synosnap` DKMS kernel module patched for kernel 6.12 API changes
- Build number bumped to 4968

### Tested on
- Debian `6.12.69+deb13-amd64`

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
