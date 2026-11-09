# shellcheck shell=bash
# ── GE-Proton runtime update path ─────────────────────────────────────────────
# GE-Proton has two sources on this image. The baseline is the build-time
# layer: the Dockerfile installs the CI-pinned GE-Proton via
# build_files/scripts/proton-cachyos.sh into
# /usr/share/steam/compatibilitytools.d/, so a fresh install has a working
# GE-Proton offline. The weekly kyth-proton-cachyos-update.timer is the
# refresh path: it installs newer GE-Proton releases to
# /var/lib/kyth/proton-cachyos/ (/var is writable on an immutable system),
# which Steam also scans via STEAM_EXTRA_COMPAT_TOOLS_PATHS. The timer is
# enabled at build time only when the updater signing anchor carries a
# real certificate (see branding/31-ujust-recipes.sh) — while the anchor
# is the placeholder the updater refuses every run — and it is disabled
# outright on the live ISO (see installer/build.sh's
# kyth-proton-cachyos-update.timer disable).
# NOTE: the timer/unit/directory keep their historical `proton-cachyos` names;
# the payload is GE-Proton from GloriousEggroll/proton-ge-custom.
# The directory must exist at first boot regardless — Lutris (and Steam) call
# os.stat() on every path in STEAM_EXTRA_COMPAT_TOOLS_PATHS and crash with
# FileNotFoundError if any are missing, even before the update service has run
# for the first time.
mkdir -p /var/lib/kyth/proton-cachyos
# 1777 was world-writable (any local user could plant a trojaned Proton).
# Use 0755 root-root; STEAM_EXTRA_COMPAT_TOOLS_PATHS scan only needs
# the directory to exist, not be writable. Per-user prefixes stay in
# ~/.local/share/Steam/steamapps/compatdata (see drives.py).
chmod 0755 /var/lib/kyth/proton-cachyos
write_line 'd /var/lib/kyth/proton-cachyos 0755 root root - -' /usr/lib/tmpfiles.d/kyth-proton-cachyos.conf
write_line 'STEAM_EXTRA_COMPAT_TOOLS_PATHS=/var/lib/kyth/proton-cachyos' /etc/environment.d/proton-cachyos.conf
