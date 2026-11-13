#!/usr/bin/env bash
# Boot a KythOS ISO through an unattended install and optional update/rollback.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}/../.." rev-parse --show-toplevel)"

usage() {
	cat <<'EOF'
Usage: vm-acceptance.sh --iso PATH [--update-ref IMAGE] [--artifacts DIR]
                        [--timeout-minutes N] [--allow-tcg] [--network-check]
                        [--installer-daemon] [--secure-boot] [--windows]

Without --update-ref, validates live boot, bundled-image installation, and the
first installed boot. With --update-ref, also stages that image, boots it,
stages rollback, and verifies the original digest after the rollback boot.

With --network-check, the guest additionally verifies that the installed
system can resolve and reach its target registry. It is off by default so
hermetic runs without outbound networking do not false-fail.

With --installer-daemon, the guest installs by driving the real installer
daemon (kyth-installerd) over its authenticated socket and asserts every
assurance check in its report, instead of running bootc directly. It is
opt-in so the raw bootc route remains the default.

With --secure-boot, the VM boots secboot OVMF firmware with the KythOS
MOK certificate pre-enrolled into a per-run copy of the variables file
(via virt-fw-vars), and the installed system must report Secure Boot
enabled. The secboot firmware is probed for and never silently replaced
with non-secboot firmware.

With --windows, a Windows side (GPT + ESP + NTFS, see
vm-acceptance-prep-windows.sh) is prepared on the install disk first and
the guest performs an alongside NTFS-shrink install, asserting the NTFS
volume's identity survives. It requires --installer-daemon: the raw
bootc route can only wipe the disk and would destroy the prepared NTFS
partition. The disk grows to 128G for this variant: the installer only
offers NTFS partitions of at least 96 GiB as shrink candidates (a 64 GiB
Windows floor plus the 32 GiB KythOS minimum), which a 64G disk can
never satisfy.

With --display MODE, the QEMU display backend is chosen explicitly.
The default is automatic: spice-app when a graphical session and
remote-viewer are present (workstation use), none on headless runners —
spice-app is fatal there because QEMU cannot launch a SPICE client.

Booting a full desktop OS under software emulation (no /dev/kvm) is too slow
to finish inside any practical timeout, so hardware acceleration is required
by default; pass --allow-tcg to run under TCG anyway (expect it to time out
except on a trivially small workload).
EOF
}

ISO=
UPDATE_REF=
ARTIFACTS=
TIMEOUT_MINUTES=75
DISPLAY_MODE=
ALLOW_TCG=0
NETWORK_CHECK=0
INSTALLER_DAEMON=0
SECURE_BOOT=0
WINDOWS=0
while (($#)); do
	case "$1" in
	--iso)
		ISO="${2:?}"
		shift 2
		;;
	--update-ref)
		UPDATE_REF="${2:?}"
		shift 2
		;;
	--artifacts)
		ARTIFACTS="${2:?}"
		shift 2
		;;
	--timeout-minutes)
		TIMEOUT_MINUTES="${2:?}"
		shift 2
		;;
	--display)
		DISPLAY_MODE="${2:?}"
		shift 2
		;;
	--allow-tcg)
		ALLOW_TCG=1
		shift
		;;
	--network-check)
		NETWORK_CHECK=1
		shift
		;;
	--installer-daemon)
		INSTALLER_DAEMON=1
		shift
		;;
	--secure-boot)
		SECURE_BOOT=1
		shift
		;;
	--windows)
		WINDOWS=1
		shift
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

[[ -n "${ISO}" && -r "${ISO}" ]] || {
	echo "Readable --iso is required" >&2
	exit 64
}
[[ "${TIMEOUT_MINUTES}" =~ ^[1-9][0-9]*$ ]] || {
	echo "Invalid timeout" >&2
	exit 64
}
# spice-app makes QEMU spawn a SPICE client (remote-viewer): right on a
# workstation, fatal on a headless runner ("Failed to launch spice+unix
# URI: Operation not supported") — QEMU exits before the guest boots and
# every readiness sentinel reports missing. Nothing in this harness
# connects to the SPICE socket (screenshots use the QEMU monitor;
# readiness uses the serial log), so auto-select: spice-app only when a
# viewer session actually exists, -display none otherwise. The SPICE
# server socket below stays either way for the guest agent channel.
if [[ -z "${DISPLAY_MODE}" ]]; then
	if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] \
		&& command -v remote-viewer >/dev/null; then
		DISPLAY_MODE="spice-app"
	else
		DISPLAY_MODE="none"
	fi
fi
[[ "${DISPLAY_MODE}" =~ ^[a-z0-9-]+$ ]] || {
	echo "Invalid --display mode: ${DISPLAY_MODE}" >&2
	exit 64
}
if ((WINDOWS)) && ((INSTALLER_DAEMON == 0)); then
	echo "--windows requires --installer-daemon: the raw bootc route can" >&2
	echo "only wipe the install disk, which would destroy the prepared" >&2
	echo "NTFS partition instead of shrinking it." >&2
	exit 64
fi
for command in qemu-img qemu-system-x86_64 timeout; do
	command -v "${command}" >/dev/null || {
		echo "Missing command: ${command}" >&2
		exit 69
	}
done

if [[ -z "${ARTIFACTS}" ]]; then
	ARTIFACTS="$(mktemp -d /tmp/kyth-vm-acceptance.XXXXXXXX)"
else
	mkdir -p "${ARTIFACTS}"
fi
ARTIFACTS="$(realpath "${ARTIFACTS}")"
ISO="$(realpath "${ISO}")"
DISK="${ARTIFACTS}/installed.qcow2"
SERIAL_LOG="${ARTIFACTS}/serial.log"
QEMU_LOG="${ARTIFACTS}/qemu.log"
MONITOR="${ARTIFACTS}/monitor.sock"
rm -f "${DISK}" "${SERIAL_LOG}" "${QEMU_LOG}" "${MONITOR}"
DISK_SIZE=64G
if ((WINDOWS)); then
	# The installer's NTFS shrink candidacy starts at 96 GiB of NTFS
	# (64 GiB Windows floor + 32 GiB KythOS minimum), so the Windows
	# variant's disk must be larger than the standard 64G.
	DISK_SIZE=128G
fi
qemu-img create -q -f qcow2 -o lazy_refcounts=on "${DISK}" "${DISK_SIZE}"

WINDOWS_NTFS_UUID=
if ((WINDOWS)); then
	"${SCRIPT_DIR}/vm-acceptance-prep-windows.sh" \
		--disk "${DISK}" --report "${ARTIFACTS}/windows-prep.txt"
	WINDOWS_NTFS_UUID="$(sed -n 's/^NTFS_UUID=//p' "${ARTIFACTS}/windows-prep.txt" | head -1)"
	[[ -n "${WINDOWS_NTFS_UUID}" ]] || {
		echo "Windows preparation did not report an NTFS volume UUID" >&2
		exit 1
	}
fi

MACHINE_ARGS=(-machine q35)
OVMF_ARGS=()
if ((SECURE_BOOT)); then
	# Secure Boot variant: secboot firmware only (never a silent
	# fallback), SMM on, and the KythOS MOK certificate pre-enrolled
	# into a per-run copy of the variables file — the system template
	# is only ever read, via virt-fw-vars -i/-o.
	MOK_CERT="${REPO_ROOT}/build_files/secureboot/kyth-secureboot.cer"
	# Owner GUID shim records MokList entries under.
	SHIM_GUID="605dab50-e046-4300-abb6-3dd810dd8b23"
	command -v virt-fw-vars >/dev/null || {
		echo "--secure-boot requires virt-fw-vars to pre-enroll the" >&2
		echo "KythOS MOK certificate (package: python3-virt-firmware)." >&2
		exit 69
	}
	[[ -r "${MOK_CERT}" ]] || {
		echo "KythOS MOK certificate is missing: ${MOK_CERT}" >&2
		exit 66
	}
	SECBOOT_PAIRS=(
		# Fedora layout: dedicated secboot variables file.
		"/usr/share/OVMF/OVMF_CODE_4M.secboot.fd:/usr/share/OVMF/OVMF_VARS_4M.secboot.fd"
		# Debian/Ubuntu layout: the secboot CODE pairs with the .ms
		# variables file (no VARS_4M.secboot.fd is shipped).
		"/usr/share/OVMF/OVMF_CODE_4M.secboot.fd:/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
		"/usr/share/OVMF/OVMF_CODE_4M.ms.fd:/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
		"/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.fd:/usr/share/edk2/ovmf/OVMF_VARS_4M.secboot.fd"
		"/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd:/usr/share/edk2-ovmf/x64/OVMF_VARS.secboot.fd"
	)
	SECBOOT_CODE=
	SECBOOT_VARS=
	for pair in "${SECBOOT_PAIRS[@]}"; do
		if [[ -r "${pair%%:*}" && -r "${pair##*:}" ]]; then
			SECBOOT_CODE="${pair%%:*}"
			SECBOOT_VARS="${pair##*:}"
			break
		fi
	done
	[[ -n "${SECBOOT_CODE}" ]] || {
		echo "Secure Boot OVMF firmware was not found. Probed pairs:" >&2
		printf '  %s\n' "${SECBOOT_PAIRS[@]}" >&2
		echo "Install the ovmf (Debian/Ubuntu) or edk2-ovmf (Fedora)" >&2
		echo "package. Refusing to fall back to non-Secure-Boot firmware." >&2
		exit 69
	}
	virt-fw-vars -i "${SECBOOT_VARS}" -o "${ARTIFACTS}/OVMF_VARS.fd" \
		--sb --add-mok "${SHIM_GUID}" "${MOK_CERT}"
	OVMF_ARGS=(
		-drive "if=pflash,format=raw,unit=0,readonly=on,file=${SECBOOT_CODE}"
		-drive "if=pflash,format=raw,unit=1,file=${ARTIFACTS}/OVMF_VARS.fd"
	)
	MACHINE_ARGS=(
		-machine "q35,smm=on"
		-global "driver=cfi.pflash01,property=secure,value=on"
	)
else
	for code in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE.fd; do
		[[ -r "${code}" ]] || continue
		vars_template="${code/CODE/VARS}"
		if [[ -r "${vars_template}" ]]; then
			cp "${vars_template}" "${ARTIFACTS}/OVMF_VARS.fd"
			OVMF_ARGS=(
				-drive "if=pflash,format=raw,unit=0,readonly=on,file=${code}"
				-drive "if=pflash,format=raw,unit=1,file=${ARTIFACTS}/OVMF_VARS.fd"
			)
			break
		fi
	done
fi

# shellcheck disable=SC2054  # commas below are qemu's own option syntax, not array separators
QEMU_ARGS=(
	"${MACHINE_ARGS[@]}"
	-smp 4
	-m 8192
	-nodefaults
	-no-user-config
	-device virtio-vga
	-display "${DISPLAY_MODE}"
	-spice "unix=on,addr=${ARTIFACTS}/spice.sock,disable-ticketing=on,disable-copy-paste=off,disable-agent-file-xfer=off"
	-device virtio-rng-pci
	-device ich9-ahci,id=ahci
	-drive "if=none,id=liveiso,format=raw,media=cdrom,readonly=on,file=${ISO}"
	# `-boot once=d` selects the ISO for the initial live boot. Keep the
	# installed disk first in the persistent device order so a guest reboot
	# after installation enters the installed system instead of reinstalling.
	-device ide-cd,bus=ahci.0,drive=liveiso,bootindex=2
	-drive "if=none,id=systemdisk,file=${DISK},format=qcow2,cache=writeback"
	-device virtio-blk-pci,drive=systemdisk,serial=KYTH_ACCEPT,bootindex=1
	-netdev user,id=net0
	-device virtio-net-pci,netdev=net0
	-serial "file:${SERIAL_LOG}"
	-D "${QEMU_LOG}"
	-monitor "unix:${MONITOR},server=on,wait=off"
	-fw_cfg name=opt/com.kyth/acceptance,string=1
	-boot once=d,menu=off
	"${OVMF_ARGS[@]}"
)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
	QEMU_ARGS+=(-enable-kvm -cpu host)
elif ((ALLOW_TCG)); then
	echo "Warning: /dev/kvm is unavailable; using slower TCG emulation" >&2
	QEMU_ARGS+=(-accel tcg -cpu max)
else
	echo "/dev/kvm is unavailable; refusing to boot a full desktop OS under" >&2
	echo "software emulation (it will not finish inside any practical timeout)." >&2
	echo "Pass --allow-tcg to override, or fix KVM access on this host." >&2
	exit 69
fi
if [[ -n "${UPDATE_REF}" ]]; then
	[[ "${UPDATE_REF}" =~ ^[A-Za-z0-9._/@:+-]+$ ]] || {
		echo "Unsafe update ref" >&2
		exit 64
	}
	QEMU_ARGS+=(-fw_cfg "name=opt/com.kyth/update-ref,string=${UPDATE_REF}")
fi
if ((NETWORK_CHECK)); then
	QEMU_ARGS+=(-fw_cfg "name=opt/com.kyth/network-check,string=1")
fi
if ((INSTALLER_DAEMON)); then
	QEMU_ARGS+=(-fw_cfg "name=opt/com.kyth/installer-mode,string=daemon")
fi
if ((SECURE_BOOT)); then
	QEMU_ARGS+=(-fw_cfg "name=opt/com.kyth/secure-boot,string=1")
fi
if ((WINDOWS)); then
	QEMU_ARGS+=(-fw_cfg "name=opt/com.kyth/windows,string=1")
fi

echo "Acceptance artifacts: ${ARTIFACTS}"
set +e
timeout --signal=TERM --kill-after=30s "${TIMEOUT_MINUTES}m" \
	qemu-system-x86_64 "${QEMU_ARGS[@]}" &
QEMU_WRAPPER_PID=$!
set -e

capture_phase() {
	local phase="$1"
	local output="$2"
	[[ -S "${MONITOR}" ]] || return 0
	printf 'screendump %s\n' "${output}" |
		socat - "UNIX-CONNECT:${MONITOR}" >/dev/null 2>&1 || true
}

captured_live=0
captured_installed=0
while kill -0 "${QEMU_WRAPPER_PID}" 2>/dev/null; do
	if command -v socat >/dev/null && [[ -r "${SERIAL_LOG}" ]]; then
		if ((captured_live == 0)) && grep -q '^KYTH_ACCEPTANCE:LIVE_READY:' "${SERIAL_LOG}"; then
			capture_phase LIVE_READY "${ARTIFACTS}/live-desktop.ppm"
			captured_live=1
		fi
		if ((captured_installed == 0)) && grep -q '^KYTH_ACCEPTANCE:INSTALLED_READY:' "${SERIAL_LOG}"; then
			capture_phase INSTALLED_READY "${ARTIFACTS}/installed-login.ppm"
			captured_installed=1
		fi
	fi
	sleep 2
done
set +e
wait "${QEMU_WRAPPER_PID}"
QEMU_STATUS=$?
set -e

cat "${SERIAL_LOG}" || true
if ((QEMU_STATUS == 124 || QEMU_STATUS == 137)); then
	echo "VM acceptance timed out after ${TIMEOUT_MINUTES} minutes" >&2
	exit 1
fi
grep -q '^KYTH_ACCEPTANCE:LIVE_READY:' "${SERIAL_LOG}" ||
	{
		echo "Live desktop readiness sentinel missing" >&2
		exit 1
	}
grep -q '^KYTH_ACCEPTANCE:INSTALL_COMPLETE:' "${SERIAL_LOG}" ||
	{
		echo "Install completion sentinel missing" >&2
		exit 1
	}
grep -q '^KYTH_ACCEPTANCE:INSTALLED_READY:' "${SERIAL_LOG}" ||
	{
		echo "Installed boot readiness sentinel missing" >&2
		exit 1
	}
grep -q '^KYTH_ACCEPTANCE:INSTALLED_SELINUX_OK:' "${SERIAL_LOG}" ||
	{
		echo "Installed SELinux enforcing sentinel missing" >&2
		exit 1
	}
grep -q '^KYTH_ACCEPTANCE:FIRSTBOOT_OK:' "${SERIAL_LOG}" ||
	{
		echo "First-boot completion sentinel missing" >&2
		exit 1
	}
grep -q '^KYTH_ACCEPTANCE:COMPLETE:' "${SERIAL_LOG}" ||
	{
		echo "Acceptance completion sentinel missing" >&2
		exit 1
	}
if ((NETWORK_CHECK)); then
	grep -q '^KYTH_ACCEPTANCE:INSTALLED_NETWORK_OK:' "${SERIAL_LOG}" ||
		{
			echo "Installed network check sentinel missing" >&2
			exit 1
		}
fi
if ((SECURE_BOOT)); then
	grep -q '^KYTH_ACCEPTANCE:INSTALLED_SECUREBOOT_OK:' "${SERIAL_LOG}" ||
		{
			echo "Installed Secure Boot sentinel missing" >&2
			exit 1
		}
fi
if ((WINDOWS)); then
	for phase in WINDOWS_NTFS_BEFORE WINDOWS_NTFS_AFTER WINDOWS_NTFS_OK; do
		grep -q "^KYTH_ACCEPTANCE:${phase}:" "${SERIAL_LOG}" ||
			{
				echo "${phase} sentinel missing" >&2
				exit 1
			}
		# The NTFS volume identity the guest reports at every stage
		# must be the one the host prepared: a shrink preserves the
		# volume serial, so any drift means the volume was recreated.
		reported_uuid="$(sed -n "s/^KYTH_ACCEPTANCE:${phase}:.*uuid=\([0-9A-Fa-f-]*\).*/\1/p" "${SERIAL_LOG}" | head -1)"
		if [[ "${reported_uuid,,}" != "${WINDOWS_NTFS_UUID,,}" ]]; then
			echo "${phase} reports NTFS uuid '${reported_uuid}', expected the prepared '${WINDOWS_NTFS_UUID}'" >&2
			exit 1
		fi
	done
fi
if [[ -n "${UPDATE_REF}" ]]; then
	for phase in UPDATE_STAGED UPDATE_BOOTED ROLLBACK_STAGED ROLLBACK_BOOTED; do
		grep -q "^KYTH_ACCEPTANCE:${phase}:" "${SERIAL_LOG}" ||
			{
				echo "${phase} sentinel missing" >&2
				exit 1
			}
	done
fi
if grep -q '^KYTH_ACCEPTANCE:FAILED:' "${SERIAL_LOG}"; then
	echo "Guest reported an acceptance failure" >&2
	exit 1
fi
((QEMU_STATUS == 0)) || {
	echo "QEMU exited with ${QEMU_STATUS}" >&2
	exit 1
}
QUALIFICATION_ARGS=(
	acceptance
	--log "${SERIAL_LOG}"
	--output "${ARTIFACTS}/qualification.json"
	--markdown "${ARTIFACTS}/qualification.md"
)
if [[ -n "${UPDATE_REF}" ]]; then
	QUALIFICATION_ARGS+=(--update-required)
fi
if ((SECURE_BOOT)); then
	QUALIFICATION_ARGS+=(--secure-boot-required)
fi
if ((WINDOWS)); then
	QUALIFICATION_ARGS+=(--windows-required)
fi
if [[ -x /usr/bin/kyth-qualify ]]; then
	qualification_cmd=(/usr/bin/kyth-qualify)
elif [[ -x "${REPO_ROOT}/src/kyth-shared-rs/target/release/kyth-qualify" ]]; then
	qualification_cmd=("${REPO_ROOT}/src/kyth-shared-rs/target/release/kyth-qualify")
elif [[ -x "${REPO_ROOT}/src/kyth-shared-rs/target/debug/kyth-qualify" ]]; then
	qualification_cmd=("${REPO_ROOT}/src/kyth-shared-rs/target/debug/kyth-qualify")
else
	qualification_cmd=(cargo run --quiet --manifest-path "${REPO_ROOT}/src/kyth-shared-rs/Cargo.toml" --bin kyth-qualify --)
fi
"${qualification_cmd[@]}" "${QUALIFICATION_ARGS[@]}"
echo "KythOS VM acceptance passed"
