#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNFILE="${1:-$SCRIPT_DIR/install.run}"
TMPDIR=$(mktemp -d)

echo "=== Extracting install.run ==="
ARCHIVE=$(awk '/^__ARCHIVE_BELOW__$/ {print NR + 1; exit 0; }' "$RUNFILE")
echo "Archive starts at line: $ARCHIVE"
tail -n+"${ARCHIVE}" "$RUNFILE" | tar xzf - -C "$TMPDIR"

echo "=== Payload contents ==="
ls "$TMPDIR/"

echo "=== variables.sh ==="
cat "$TMPDIR/variables.sh"

echo ""
echo "=== Agent DEB version ==="
dpkg-deb -I "$TMPDIR/Synology Active Backup for Business Agent-3.1.0-4969.deb" control 2>/dev/null | grep Version || echo "Agent DEB not found"

echo ""
echo "=== Verifying binary patch ==="
AGENTDIR=$(mktemp -d)
dpkg-deb -R "$TMPDIR/Synology Active Backup for Business Agent-3.1.0-4969.deb" "$AGENTDIR" 2>/dev/null
grep -ao "build.4969" "$AGENTDIR/bin/abb-cli" 2>/dev/null && echo "abb-cli: PATCHED" || echo "abb-cli: NOT patched"
grep -ao "build.4969" "$AGENTDIR/opt/Synology/ActiveBackupforBusiness/bin/service-ctrl" 2>/dev/null && echo "service-ctrl: PATCHED" || echo "service-ctrl: NOT patched"
grep -ao "build.4969" "$AGENTDIR/opt/Synology/ActiveBackupforBusiness/bin/synology-backupd" 2>/dev/null && echo "synology-backupd: PATCHED" || echo "synology-backupd: NOT patched"

echo ""
echo "=== Synosnap patched sources ==="
SNAPDIR=$(mktemp -d)
dpkg-deb -R "$TMPDIR/synosnap-0.11.6.deb" "$SNAPDIR" 2>/dev/null
ls "$SNAPDIR/usr/src/synosnap-0.11.6/configure-tests/feature-tests/bdev_file_open_by_path.c" >/dev/null 2>&1 && echo "bdev_file_open_by_path.c: OK" || echo "bdev_file_open_by_path.c: MISSING"
ls "$SNAPDIR/usr/src/synosnap-0.11.6/configure-tests/feature-tests/bdev_test_flag.c" >/dev/null 2>&1 && echo "bdev_test_flag.c: OK" || echo "bdev_test_flag.c: MISSING"
ls "$SNAPDIR/usr/src/synosnap-0.11.6/configure-tests/feature-tests/bio_qos_throttled.c" >/dev/null 2>&1 && echo "bio_qos_throttled.c: OK" || echo "bio_qos_throttled.c: MISSING"
ls "$SNAPDIR/usr/src/synosnap-0.11.6/configure-tests/feature-tests/submit_bio_noacct_void.c" >/dev/null 2>&1 && echo "submit_bio_noacct_void.c: OK" || echo "submit_bio_noacct_void.c: MISSING"
grep -qc "fd_file" "$SNAPDIR/usr/src/synosnap-0.11.6/includes.h" 2>/dev/null && echo "includes.h: patched (fd_file)" || echo "includes.h: NOT patched"
grep -qc "BIO_QOS_THROTTLED" "$SNAPDIR/usr/src/synosnap-0.11.6/includes.h" 2>/dev/null && echo "includes.h: patched (BIO_QOS_THROTTLED)" || echo "includes.h: NOT patched (BIO_QOS_THROTTLED)"
grep -qc "run_one_test" "$SNAPDIR/usr/src/synosnap-0.11.6/genconfig.sh" 2>/dev/null && echo "genconfig.sh: patched (run_one_test)" || echo "genconfig.sh: NOT patched"
grep -qc "KERNEL_VERSION(6,12,0)" "$SNAPDIR/usr/src/synosnap-0.11.6/ftrace_hooking.c" 2>/dev/null && echo "ftrace_hooking.c: patched (6.12)" || echo "ftrace_hooking.c: NOT patched"
grep -qc "KERNEL_VERSION(6,15,0)" "$SNAPDIR/usr/src/synosnap-0.11.6/ftrace_hooking.c" 2>/dev/null && echo "ftrace_hooking.c: patched (6.15)" || echo "ftrace_hooking.c: NOT patched (6.15)"
ls "$SNAPDIR/usr/src/synosnap-0.11.6/mrf.c" >/dev/null 2>&1 && echo "mrf.c: OK" || echo "mrf.c: MISSING"

rm -rf "$TMPDIR" "$AGENTDIR" "$SNAPDIR"
echo ""
echo "=== All checks complete ==="
