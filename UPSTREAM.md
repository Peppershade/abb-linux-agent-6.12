# Synology, Axcient, and the synosnap kernel module

## The short version

Synology's `synosnap` kernel module, the component that makes
Active Backup for Business work on Linux, is built on top of open-source
code maintained by [Axcient](https://github.com/Axcient/elastio-snap).
When the Linux kernel breaks compatibility, Axcient is usually the first
to fix it. Synology then ships those fixes as part of a new agent release.

This project exists for the gap in between.

---

## The code lineage

```
Datto Inc. (2015)
  └─ dattobd — original block device snapshot driver
       └─ Elastio Software (2020)
            └─ elastio-snap — forked and extended
                 └─ Axcient (2024, forked elastio-snap)
                      └─ elastio-snap — actively maintained
                           └─ Synology
                                └─ synosnap — renamed, repackaged,
                                              integrated into ABB agent
```

The copyright chain is intact: `main.c` still carries the original
Datto (2015) and Elastio (2020) notices. Axcient's newer additions
(the kernel 6.8+ compatibility layer, `struct bdev_container`, etc.)
are present in the code but not yet reflected in the copyright header,
that's Axcient's own housekeeping, not a Synology issue.

---

## The update cycle

Active Backup for Business is a mature product, and Synology does
eventually ship kernel compatibility updates. The keyword is *eventually*.

Here's the most recent example:

| Event | Date |
|---|---|
| Axcient adds kernel 6.12 compatibility (`freeze_super` rework) | February 2025 |
| Axcient adds kernel 6.15 support | July 2025 |
| Synology ships `3.2.0-5053` with kernel 6.12–6.14 support | March 2026 |

**13 months** passed between Axcient having the fix ready and Synology
shipping it. To be fair, Synology maintains the entire ABB suite, not
just the kernel module, and carries their own customisations on top of
the upstream driver that need to be integrated and tested with each
update. That is real work. But 13 months for a kernel compatibility fix
that already existed upstream is still a long time, and for a commercial
backup product targeting Linux servers it is hard to defend. Users on
Ubuntu 25.04 (kernel 6.14) and 25.10 (kernel 6.17+) were left without
working backups for over a year, not because the fix didn't exist, but
because Synology hadn't gotten around to shipping it yet.

---

## What this project does

This project patches the `synosnap` module ahead of Synology's official
releases. Some fixes are pulled from Axcient's upstream development,
others are written here independently when the kernel moves faster than
either upstream keeps up with. The version number is bumped only slightly
(e.g. `3.2.0-5054` over the official `3.2.0-5053`) so that when Synology
does ship an official update, ABB will automatically install their version
over ours.

See [UPSTREAM_STATUS.md](UPSTREAM_STATUS.md) for the current gap between
Axcient's latest and what Synology ships.

---

## Links

- [Axcient elastio-snap](https://github.com/Axcient/elastio-snap), upstream kernel module
- [Synology Active Backup for Business](https://www.synology.com/en-global/dsm/feature/active_backup_business), the product
- [Current upstream status](UPSTREAM_STATUS.md), auto-updated weekly
