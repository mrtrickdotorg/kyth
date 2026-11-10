#!/usr/bin/env bash
# Prepare the Windows side of a KythOS VM acceptance disk: a GPT with a
# 512 MiB EFI System Partition and an NTFS partition labelled "Windows"
# spanning the rest of the disk, carrying a minimal Windows/System32
# marker tree.
#
# What the installer actually detects (installer_storage.rs,
# installer_plan.rs, installer_daemon.rs): an NTFS filesystem type via
# blkid, the Microsoft basic-data partition GUID or a "windows" label
# for its Windows-presence preflight, candidacy via the partition's
# size/flags (ntfs_resize_candidate), and at commit time a clean NTFS
# volume (ntfsfix --no-action). No installer stage reads files inside
# the NTFS volume; the marker tree exists so the fixture reads as a
# Windows disk to humans and to any future content check, not because
# detection needs it.
#
# The NTFS partition must end up at least 96 GiB or the installer will
# never offer it as a shrink candidate (NTFS_MIN_BYTES in
# installer_storage.rs: a 64 GiB Windows floor plus the 32 GiB KythOS
# minimum), so this script refuses disks that cannot satisfy that.
#
# Backends: guestfish (Debian/Ubuntu package: libguestfs-tools) when
# available, else qemu-nbd (qemu-utils) with sfdisk (fdisk), mkntfs
# (ntfs-3g) and mkfs.vfat (dosfstools). Both need a cooperative host
# kernel: libguestfs builds its appliance from the host kernel's
# modules, and qemu-nbd needs the nbd module loadable. When neither
# backend is usable the script fails naming the missing packages
# instead of preparing a half-plausible disk.

set -euo pipefail

usage() {
	cat <<'EOF'
Usage: vm-acceptance-prep-windows.sh --disk PATH [--report PATH]

Writes a GPT + ESP + NTFS "Windows" layout onto an existing, still
unpartitioned disk image (qcow2 or raw). Prints NTFS_UUID=<uuid> on
stdout and, with --report, writes the run's facts to that file for the
caller to compare against the guest's post-install evidence.
EOF
}

DISK=
REPORT=
while (($#)); do
	case "$1" in
	--disk)
		DISK="${2:?}"
		shift 2
		;;
	--report)
		REPORT="${2:?}"
		shift 2
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		echo "Unknown argument: $1" >&2
		usage >&2
		exit 64
		;;
	esac
done

[[ -n "${DISK}" && -f "${DISK}" ]] || {
	echo "An existing --disk image is required" >&2
	exit 64
}
command -v qemu-img >/dev/null || {
	echo "Missing command: qemu-img (package: qemu-utils)" >&2
	exit 69
}

ESP_START_SECTOR=2048
ESP_SECTORS=1048576 # 512 MiB
NTFS_START_SECTOR=$((ESP_START_SECTOR + ESP_SECTORS))
ESP_GUID="C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
NTFS_GUID="EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
MARKER_TEXT="KythOS VM acceptance placeholder: not a real Windows install."

# qemu-img nests child-node info (with its own small virtual-size)
# before the top-level entry; the disk's size is the largest value.
DISK_BYTES="$(qemu-img info --output=json "${DISK}" | sed -n 's/.*"virtual-size": \([0-9][0-9]*\).*/\1/p' | sort -n | tail -1)"
[[ "${DISK_BYTES}" =~ ^[0-9]+$ ]] || {
	echo "Could not read the virtual size of ${DISK}" >&2
	exit 1
}
NTFS_BYTES=$((DISK_BYTES - NTFS_START_SECTOR * 512 - 1048576))
if ((NTFS_BYTES < 96 * 1024 * 1024 * 1024)); then
	echo "Disk is too small for a Windows alongside fixture: the NTFS" >&2
	echo "partition would be $((NTFS_BYTES / 1024 / 1024)) MiB, below the" >&2
	echo "installer's 96 GiB NTFS shrink-candidacy minimum (64 GiB Windows" >&2
	echo "floor + 32 GiB KythOS minimum). Use a disk of at least 97 GiB." >&2
	exit 64
fi

BACKEND=
NTFS_UUID=

prep_with_guestfish() {
	# Refuse to overwrite an existing layout: the host wrapper always
	# passes a freshly created image, so partitions mean a scripting
	# bug or the wrong file.
	local existing
	existing="$(guestfish --ro -a "${DISK}" run : list-partitions 2>/dev/null || true)"
	[[ -z "${existing}" ]] || {
		echo "${DISK} already has partitions; refusing to overwrite them" >&2
		exit 1
	}
	guestfish --rw -a "${DISK}" <<EOF
run
part-init /dev/sda gpt
part-add /dev/sda p ${ESP_START_SECTOR} $((NTFS_START_SECTOR - 1))
part-add /dev/sda p ${NTFS_START_SECTOR} -2048
part-set-gpt-type /dev/sda 1 ${ESP_GUID}
part-set-gpt-type /dev/sda 2 ${NTFS_GUID}
mkfs vfat /dev/sda1
mkfs ntfs /dev/sda2
set-label /dev/sda1 EFI
set-label /dev/sda2 Windows
mount /dev/sda2 /
mkdir /Windows
mkdir /Windows/System32
write /Windows/System32/ntoskrnl.exe "${MARKER_TEXT}"
umount-all
EOF
	NTFS_UUID="$(guestfish --ro -a "${DISK}" run : vfs-uuid /dev/sda2 | tail -1 | tr -d '[:space:]')"
}

NBD_DEVICE=
NBD_MOUNT=
cleanup_nbd() {
	if [[ -n "${NBD_MOUNT}" ]]; then
		umount "${NBD_MOUNT}" 2>/dev/null || true
		NBD_MOUNT=
	fi
	if [[ -n "${NBD_DEVICE}" ]]; then
		qemu-nbd --disconnect "${NBD_DEVICE}" >/dev/null 2>&1 || true
		NBD_DEVICE=
	fi
}

prep_with_qemu_nbd() {
	# Find a free nbd device, loading the module when possible.
	if [[ ! -e /dev/nbd0 ]]; then
		if [[ "$(id -u)" == "0" ]]; then
			modprobe nbd max_part=16 2>/dev/null || true
		elif command -v sudo >/dev/null; then
			sudo -n modprobe nbd max_part=16 2>/dev/null || true
		fi
	fi
	local index
	for index in 0 1 2 3 4 5 6 7; do
		if [[ -b "/dev/nbd${index}" ]] &&
			[[ "$(cat "/sys/block/nbd${index}/size" 2>/dev/null || echo 0)" == "0" ]]; then
			NBD_DEVICE="/dev/nbd${index}"
			break
		fi
	done
	[[ -n "${NBD_DEVICE}" ]] || {
		echo "No usable /dev/nbd* device: the nbd kernel module is not" >&2
		echo "loaded and could not be loaded. Install the guestfish" >&2
		echo "backend instead (package: libguestfs-tools)." >&2
		exit 69
	}
	trap cleanup_nbd EXIT
	qemu-nbd --connect="${NBD_DEVICE}" "${DISK}"
	# Wait for the partition devices to settle.
	local part1="${NBD_DEVICE}p1" part2="${NBD_DEVICE}p2"
	local attempt
	for attempt in $(seq 1 20); do
		[[ -b "${NBD_DEVICE}" ]] && break
		sleep 0.5
	done
	if sfdisk -l "${NBD_DEVICE}" 2>/dev/null | grep -q "${NBD_DEVICE}p"; then
		echo "${DISK} already has partitions; refusing to overwrite them" >&2
		exit 1
	fi
	sfdisk --quiet "${NBD_DEVICE}" <<EOF
label: gpt
${part1} : start=${ESP_START_SECTOR}, size=${ESP_SECTORS}, type=${ESP_GUID}, name="EFI System Partition"
${part2} : start=${NTFS_START_SECTOR}, type=${NTFS_GUID}, name="Windows"
EOF
	partprobe "${NBD_DEVICE}" 2>/dev/null || true
	for attempt in $(seq 1 20); do
		[[ -b "${part2}" ]] && break
		sleep 0.5
	done
	[[ -b "${part1}" && -b "${part2}" ]] || {
		echo "Partition devices ${part1}/${part2} did not appear" >&2
		exit 1
	}
	mkfs.vfat -F 32 -n EFI "${part1}" >/dev/null
	mkntfs -Q -L Windows "${part2}" >/dev/null
	NBD_MOUNT="$(mktemp -d /tmp/kyth-ntfs-prep.XXXXXXXX)"
	if ! mount -t ntfs3 "${part2}" "${NBD_MOUNT}" 2>/dev/null &&
		! mount -t ntfs-3g "${part2}" "${NBD_MOUNT}" 2>/dev/null; then
		echo "Could not mount the prepared NTFS partition (tried the" >&2
		echo "ntfs3 kernel driver and ntfs-3g) to plant the marker tree." >&2
		exit 1
	fi
	mkdir -p "${NBD_MOUNT}/Windows/System32"
	printf '%s\n' "${MARKER_TEXT}" >"${NBD_MOUNT}/Windows/System32/ntoskrnl.exe"
	umount "${NBD_MOUNT}"
	NBD_MOUNT=
	NTFS_UUID="$(blkid -s UUID -o value "${part2}")"
	qemu-nbd --disconnect "${NBD_DEVICE}" >/dev/null
	NBD_DEVICE=
	trap - EXIT
}

# Backend selection probes viability, not just presence: a guestfish
# binary whose appliance cannot launch (e.g. a host kernel without a
# module tree) must fall through to the nbd backend, not fail the run
# after being chosen.
if command -v guestfish >/dev/null &&
	guestfish --ro -a "${DISK}" run : list-partitions >/dev/null 2>&1; then
	BACKEND="guestfish"
elif command -v qemu-nbd >/dev/null && command -v sfdisk >/dev/null &&
	command -v mkntfs >/dev/null && command -v mkfs.vfat >/dev/null &&
	command -v blkid >/dev/null; then
	BACKEND="qemu-nbd"
fi
if [[ "${BACKEND}" == "guestfish" ]]; then
	prep_with_guestfish
elif [[ "${BACKEND}" == "qemu-nbd" ]]; then
	prep_with_qemu_nbd
else
	cat >&2 <<'EOF'
Cannot prepare a Windows fixture: no usable backend.

Preferred backend: guestfish (package: libguestfs-tools).
Fallback backend: qemu-nbd (package: qemu-utils) plus sfdisk
(package: fdisk), mkntfs (package: ntfs-3g), mkfs.vfat (package:
dosfstools) and blkid (package: util-linux).
EOF
	exit 69
fi

[[ -n "${NTFS_UUID}" ]] || {
	echo "Preparation finished without an NTFS volume UUID (${BACKEND} backend)" >&2
	exit 1
}

if [[ -n "${REPORT}" ]]; then
	{
		echo "BACKEND=${BACKEND}"
		echo "NTFS_UUID=${NTFS_UUID}"
		echo "NTFS_PARTITION=2"
		echo "ESP_PARTITION=1"
	} >"${REPORT}"
fi
echo "Prepared Windows fixture on ${DISK} via ${BACKEND}: NTFS_UUID=${NTFS_UUID}"
