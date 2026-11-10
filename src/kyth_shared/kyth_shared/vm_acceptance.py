"""Guest-side state machine and shared policy for KythOS VM acceptance."""
from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import os
import pwd
import re
import signal
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import quote

from kyth_shared.commands import run, run_text

FW_CFG_ROOT = Path("/sys/firmware/qemu_fw_cfg/by_name/opt/com.kyth")
ENABLE_FILE = FW_CFG_ROOT / "acceptance/raw"
UPDATE_FILE = FW_CFG_ROOT / "update-ref/raw"
NETWORK_CHECK_FILE = FW_CFG_ROOT / "network-check/raw"
INSTALLER_MODE_FILE = FW_CFG_ROOT / "installer-mode/raw"
SECURE_BOOT_FILE = FW_CFG_ROOT / "secure-boot/raw"
WINDOWS_FILE = FW_CFG_ROOT / "windows/raw"
# The smallest NTFS partition the installer offers as a shrink
# candidate (installer_storage.rs NTFS_MIN_BYTES: a 64 GiB Windows
# floor plus the 32 GiB KythOS minimum). The host's --windows variant
# sizes its disk so the prepared NTFS partition clears this bar.
NTFS_RESIZE_MIN_BYTES = (64 + 32) * 1024 * 1024 * 1024
WINDOWS_FLOOR_GIB = 64
INSTALLER_RUN_DIR = Path("/run/kyth-installer")
INSTALLER_SOCKET = INSTALLER_RUN_DIR / "api.sock"
INSTALLER_TOKEN_FILE = INSTALLER_RUN_DIR / "session-token"
INSTALLER_LOCK_FILE = Path("/run/lock/kyth-installer.lock")
ACCEPTANCE_HOSTNAME = "kyth-acceptance"
ACCEPTANCE_USERNAME = "kyth-acceptance"
# Throwaway password for the throwaway acceptance account on a VM that is
# discarded after the run; the daemon requires a non-empty login password
# at its API boundary (validate_start_acknowledgements).
ACCEPTANCE_PASSWORD = "kyth-acceptance"
# The stream wait must leave headroom inside the guest unit's 1800s
# TimeoutStartSec for daemon preparation and report evaluation.
DAEMON_STREAM_BUDGET_SECONDS = 1500
# Assurance check names emitted by installer_assurance::validate. The
# daemon's report mixes these with other progress checks (power,
# boot_entries); only the assurance set must be present and passing.
ASSURANCE_CHECK_NAMES = (
    "hostname", "locale", "keymap", "timezone", "account",
    "filesystem", "selinux", "encryption", "kernel", "bootloader",
)
STATE_DIR = Path("/var/lib/kyth/vm-acceptance")
STATE_FILE = STATE_DIR / "state"
SERIAL_DEVICE = Path("/dev/ttyS0")
LOG_FILE = Path("/var/log/kyth-vm-acceptance.log")
TARGET_BY_ID = Path("/dev/disk/by-id/virtio-KYTH_ACCEPT")
INSTALLER_ENV_FILE = Path("/etc/kyth-installer.env")
HUB_BINARY = Path("/usr/bin/kyth-hub-shell")
HUB_ROUTE_MANIFEST = Path("/usr/share/kyth/hubRoutes.json")
HUB_ACCEPTANCE_TIMEOUT = 45
UPDATE_REF_PATTERN = re.compile(r"^[A-Za-z0-9._/@:+-]+$")


from .atomic_io import atomic_write_text as _atomic_write


def _read_fw_cfg(path: Path) -> str:
    try:
        return path.read_bytes().replace(b"\0", b"").decode().strip()
    except OSError:
        return ""


def enabled() -> bool:
    return _read_fw_cfg(ENABLE_FILE) == "1"


def read_update_ref() -> str:
    return _read_fw_cfg(UPDATE_FILE)


def network_check_enabled() -> bool:
    return _read_fw_cfg(NETWORK_CHECK_FILE) == "1"


def installer_daemon_mode() -> bool:
    """Opt-in (fw_cfg ``installer-mode=daemon``) install route: drive the
    real installer daemon instead of the raw bootc path. Off by default."""
    return _read_fw_cfg(INSTALLER_MODE_FILE) == "daemon"


def secure_boot_mode() -> bool:
    """Variant flag (fw_cfg ``secure-boot``): the host booted secboot
    OVMF firmware with the KythOS MOK certificate pre-enrolled, so the
    installed lifecycle must prove Secure Boot really is enabled."""
    return _read_fw_cfg(SECURE_BOOT_FILE) == "1"


def windows_mode() -> bool:
    """Variant flag (fw_cfg ``windows``): the host prepared a Windows
    side (GPT + ESP + NTFS) on the acceptance disk, so the daemon route
    must perform an alongside NTFS-shrink install and the installed
    lifecycle must prove the NTFS volume survived."""
    return _read_fw_cfg(WINDOWS_FILE) == "1"


def valid_update_ref(value: str) -> bool:
    return not value or UPDATE_REF_PATTERN.fullmatch(value) is not None


def emit(phase: str, detail: str = "") -> None:
    line = f"KYTH_ACCEPTANCE:{phase}:{detail.replace(chr(10), ' ')}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
    except OSError:
        pass
    try:
        SERIAL_DEVICE.write_text(line + "\n", encoding="utf-8")
    except OSError:
        pass


def power(action: str) -> None:
    run(["systemctl", action, "--no-block"])


def fail(message: str) -> None:
    emit("FAILED", message)
    power("poweroff")
    raise SystemExit(1)


def wait_for_desktop(mode: str, *, attempts: int = 90, delay: float = 2) -> bool:
    for _ in range(attempts):
        command = (
            ["pgrep", "-x", "plasmashell"]
            if mode == "live"
            else ["systemctl", "is-active", "--quiet", "display-manager.service"]
        )
        result = run_text(command, timeout=5)
        if result is not None and result.returncode == 0:
            return True
        time.sleep(delay)
    return False


def booted_digest() -> str:
    result = run_text(["bootc", "status", "--format", "json"], timeout=30)
    if result is None or result.returncode:
        return ""
    try:
        booted = json.loads(result.stdout).get("status", {}).get("booted", {})
        image = booted.get("image", {})
        return image.get("imageDigest") or image.get("image", {}).get("imageDigest") or ""
    except (AttributeError, json.JSONDecodeError):
        return ""


def deployment_count() -> int:
    result = run_text(["ostree", "admin", "status", "--json"], timeout=30)
    if result is None or result.returncode:
        return 0
    try:
        data = json.loads(result.stdout)
        # A bare top-level list is handled before calling .get(): list has no
        # .get, so checking isinstance() only inside the default-value
        # argument would never run — .get itself raises AttributeError first.
        deployments = data if isinstance(data, list) else data.get("deployments", [])
        return len(deployments)
    except (AttributeError, json.JSONDecodeError, TypeError):
        return 0


def run_smoke_check(phase: str) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as log:
            result = run(
                ["/usr/bin/kyth-smoke-check", "--verbose"],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
    except OSError:
        fail(f"{phase} smoke check could not run")
    try:
        SERIAL_DEVICE.write_bytes(LOG_FILE.read_bytes())
    except OSError:
        pass
    if result.returncode >= 2:
        fail(f"{phase} smoke check reported failed invariants (exit {result.returncode})")
    emit(f"{phase}_SMOKE_OK", f"warnings-allowed={result.returncode}")


def _selinux_enforcing() -> None:
    result = run_text(["getenforce"], timeout=10)
    mode = result.stdout.strip() if result is not None else ""
    if result is None or result.returncode != 0 or mode != "Enforcing":
        fail(f'installed system reports SELinux mode "{mode}", expected Enforcing')
    emit("INSTALLED_SELINUX_OK", "Enforcing")


def _failed_units(output: str) -> list[str]:
    units = []
    for line in output.splitlines():
        stripped = line.strip().lstrip("●").strip()
        if stripped:
            units.append(stripped.split()[0])
    return units


def _first_boot_check() -> None:
    result = run_text(["systemctl", "--failed", "--no-legend"], timeout=30)
    if result is None or result.returncode != 0:
        fail("systemctl --failed did not complete")
    failed = _failed_units(result.stdout)
    if failed:
        fail(
            f"installed system has {len(failed)} failed unit(s): "
            + ", ".join(failed)
        )
    result = run_text(
        ["systemctl", "show", "-p", "Result", "--value", "kyth-hw-setup.service"],
        timeout=10,
    )
    value = result.stdout.strip() if result is not None else ""
    if result is None or result.returncode != 0 or value != "success":
        fail(f'kyth-hw-setup.service finished with Result="{value}", expected "success"')
    emit("FIRSTBOOT_OK", str(len(failed)))


def _registry_host(reference: str) -> str:
    return reference.split("/", 1)[0]


def _network_check() -> None:
    host = _registry_host(_installer_target_ref())
    resolved = run_text(["getent", "hosts", host], timeout=10)
    if resolved is None or resolved.returncode != 0:
        fail(f"registry host {host} did not resolve")
    probe = run_text(
        [
            "curl", "-fsS", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", "30", f"https://{host}/v2/",
        ],
        timeout=40,
    )
    code_text = probe.stdout.strip() if probe is not None else ""
    try:
        code = int(code_text)
    except ValueError:
        code = 0
    if not 100 <= code < 500:
        fail(f'registry {host} answered HTTP "{code_text}", expected a status below 500')
    emit("INSTALLED_NETWORK_OK", str(code))


def _installer_target_ref() -> str:
    default = "ghcr.io/mrtrickdotorg/kyth:testing"
    try:
        for line in INSTALLER_ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("KYTH_TARGET_IMAGE="):
                return line.partition("=")[2].strip().strip("'\"") or default
    except OSError:
        pass
    return default


def _installer_source_ref() -> str:
    try:
        for line in INSTALLER_ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("KYTH_SOURCE_IMAGE="):
                value = line.partition("=")[2].strip().strip("'\"")
                if value:
                    return value
    except OSError:
        pass
    fail("pinned installer source is missing from live image")
    return ""


def install_from_live_iso() -> None:
    if not wait_for_desktop("live"):
        fail("live Plasma desktop did not become ready")
    emit("LIVE_READY", "plasmashell-active")
    run_smoke_check("LIVE")
    for _ in range(60):
        if TARGET_BY_ID.is_block_device():
            break
        time.sleep(1)
    try:
        target = TARGET_BY_ID.resolve(strict=True)
    except OSError:
        fail("dedicated acceptance disk not found")
    if not target.is_block_device():
        fail("acceptance disk symlink did not resolve to a block device")
    source_ref = _installer_source_ref()
    target_ref = _installer_target_ref()
    emit("INSTALL_STARTED", str(target))
    try:
        with LOG_FILE.open("a", encoding="utf-8") as log:
            result = run(
                [
                    "bootc", "install", "to-disk", "--source-imgref", source_ref,
                    "--target-imgref", target_ref, "--filesystem", "btrfs",
                    "--wipe", "--skip-fetch-check", str(target),
                ],
                stdout=log, stderr=subprocess.STDOUT, timeout=1800,
            )
    except OSError:
        fail("bootc install to-disk failed")
    if result.returncode:
        fail("bootc install to-disk failed")
    update_ref = read_update_ref()
    if not valid_update_ref(update_ref):
        fail("update image reference contains unsupported characters")
    emit("INSTALL_COMPLETE", target_ref)
    power("reboot")


def _daemon_start_request(disk: str, hostname: str, username: str, password: str) -> dict[str, object]:
    """The /api/start body for a wipe install, mirroring the web
    frontend's InstallRequest field set and the values
    native_request_from_start + validate_start_acknowledgements require:
    the confirmations and the irreversible acknowledgement true, a login
    username and password present, ``encryption`` "none" (the daemon
    default). The image source is NOT a request field — the daemon reads
    KYTH_SOURCE_IMAGE from its own EnvironmentFile — so the caller
    fail-closes on the pin separately via _installer_source_ref()."""
    return {
        "disk": disk,
        "install_mode": "wipe",
        "target_partition": "",
        "resize_partition": "",
        "resize_gib": 0,
        "free_region_start": 0,
        "free_region_end": 0,
        "hostname": hostname,
        "timezone": "UTC",
        "locale": "en_US.UTF-8",
        "keymap": "us",
        "username": username,
        "password": password,
        "mok_password": "",
        "kernel": "fedora",
        "confirm_backup": True,
        "confirm_erase": True,
        "confirm_current": False,
        "encryption": "none",
        "tpm_recovery_ack": False,
        "acknowledged_irreversible": True,
        "flatpaks": [],
    }


def _acceptance_disk_from_inventory(inventory: object, target: Path) -> str | None:
    """Pick the dedicated acceptance disk out of the /api/disks
    inventory. The raw path identifies the target by resolving
    /dev/disk/by-id/virtio-KYTH_ACCEPT (the QEMU serial the host wrapper
    assigns); the inventory carries no serial, so the resolved device
    path is matched against each record's ``name``. A record flagged
    ``current`` hosts the live system and is never eligible."""
    if not isinstance(inventory, list):
        return None
    for disk in inventory:
        if not isinstance(disk, dict):
            continue
        name = disk.get("name")
        if name == str(target) and disk.get("current") is not True:
            return name
    return None


def _windows_resize_gib(size_bytes: int) -> int | None:
    """How many GiB KythOS takes when shrinking an NTFS partition of
    ``size_bytes``: everything above the 64 GiB Windows floor, or None
    when the partition is below the installer's own candidacy minimum
    (so the result always satisfies MIN_KYTHOS_GIB = 32)."""
    if size_bytes < NTFS_RESIZE_MIN_BYTES:
        return None
    return size_bytes // (1024 * 1024 * 1024) - WINDOWS_FLOOR_GIB


def _windows_resize_target_from_partitions(
    partitions: object,
) -> tuple[str, int] | None:
    """Pick the NTFS shrink target out of the daemon's /api/partitions
    inventory: the record the installer itself flags
    ``ntfs_resize_candidate`` (the same candidacy the web UI offers),
    paired with the computed shrink size."""
    if not isinstance(partitions, list):
        return None
    for partition in partitions:
        if not isinstance(partition, dict):
            continue
        if partition.get("ntfs_resize_candidate") is not True:
            continue
        name = partition.get("name")
        size = partition.get("size_bytes")
        if not isinstance(name, str) or not isinstance(size, int):
            continue
        gib = _windows_resize_gib(size)
        if gib is not None:
            return name, gib
    return None


def _daemon_windows_start_request(
    disk: str,
    hostname: str,
    username: str,
    password: str,
    resize_partition: str,
    resize_gib: int,
) -> dict[str, object]:
    """The /api/start body for the --windows variant: identical field
    set to _daemon_start_request, but an NTFS shrink (alongside)
    install of the prepared Windows partition."""
    request = _daemon_start_request(disk, hostname, username, password)
    request["install_mode"] = "resize_ntfs"
    request["resize_partition"] = resize_partition
    request["resize_gib"] = resize_gib
    return request


def _ntfs_entries_from_lsblk(output: str) -> list[tuple[str, str]]:
    """Parse `lsblk -npro NAME,FSTYPE,UUID` output into the NTFS rows:
    (device, volume UUID). The NTFS volume UUID (its serial) is the
    identity the alongside assertions compare before/after — an
    ntfsresize shrink does not change it, so a changed or missing UUID
    means the volume did not survive."""
    entries: list[tuple[str, str]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name, fstype = fields[0], fields[1]
        if fstype.lower() not in ("ntfs", "ntfs3"):
            continue
        entries.append((name, fields[2] if len(fields) > 2 else ""))
    return entries


def _secure_boot_state_from_output(output: str) -> bool | None:
    """Parse `mokutil --sb-state` output ("SecureBoot enabled" /
    "SecureBoot disabled"). None when the state cannot be determined."""
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("SecureBoot"):
            continue
        state = stripped.removeprefix("SecureBoot").strip().lower()
        if state.startswith("enabled"):
            return True
        if state.startswith("disabled"):
            return False
    return None


def _ntfs_uuids(device: str | None = None) -> list[tuple[str, str]]:
    """NTFS volumes visible on one device (or every device), as
    (device, UUID) pairs."""
    command = ["lsblk", "-npro", "NAME,FSTYPE,UUID"]
    if device is not None:
        command.append(device)
    result = run_text(command, timeout=30)
    if result is None or result.returncode:
        return []
    return _ntfs_entries_from_lsblk(result.stdout)


def _secure_boot_check() -> None:
    """Secure Boot variant truth: the installed system must report
    Secure Boot enabled — the variant boots secboot firmware with the
    KythOS MOK pre-enrolled, so a disabled or unreadable state means
    the signed boot chain did not engage."""
    result = run_text(["mokutil", "--sb-state"], timeout=10)
    if result is None or result.returncode:
        fail("mokutil --sb-state did not complete")
    state = _secure_boot_state_from_output(result.stdout if result else "")
    if state is True:
        emit("INSTALLED_SECUREBOOT_OK", "enabled")
    elif state is False:
        fail("installed system reports Secure Boot disabled")
    else:
        fail("could not determine the installed Secure Boot state from mokutil output")


def _windows_ntfs_check() -> None:
    """Windows variant truth for the installed lifecycle: an NTFS
    volume with a readable UUID must still exist after the alongside
    install and the reboot into the installed system."""
    for device, uuid in _ntfs_uuids():
        if uuid:
            emit("WINDOWS_NTFS_OK", f"device={device} uuid={uuid}")
            return
    fail("no NTFS partition with a volume UUID survived the alongside install")


def _report_failures(report: object) -> list[str]:
    """Evaluate a /api/report body: the failure list is empty only when
    the job completed and every assurance check is present and passing.
    Non-assurance progress checks fail the run only on an explicit
    "fail" status — the daemon legitimately records "warning" entries
    (e.g. boot_entries) on successful installs."""
    failures: list[str] = []
    status = report.get("status") if isinstance(report, dict) else None
    if isinstance(status, str) and status != "complete":
        failures.append(f'installer job status is "{status}"')
    checks = report.get("checks") if isinstance(report, dict) else None
    if not isinstance(checks, list) or not checks:
        failures.append("installer report carries no checks")
        return failures
    by_name: dict[str, dict] = {}
    for check in checks:
        if isinstance(check, dict) and isinstance(check.get("name"), str):
            by_name.setdefault(check["name"], check)
    for name in ASSURANCE_CHECK_NAMES:
        check = by_name.get(name)
        if check is None:
            failures.append(f"assurance check {name} is missing")
        elif check.get("status") != "pass":
            failures.append(f"assurance check {name} did not pass")
    for check in checks:
        if (
            isinstance(check, dict)
            and check.get("status") == "fail"
            and check.get("name") not in ASSURANCE_CHECK_NAMES
        ):
            failures.append(f"installer check {check.get('name', 'unknown')} failed")
    return failures


def _daemon_error_message(body: str) -> str:
    """Best-effort extraction of the daemon's error message from a
    response body ({"message": ...} or {"error": ...})."""
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        for key in ("message", "error"):
            message = value.get(key)
            if isinstance(message, str):
                return message
    return body[:512]


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 over the daemon's Unix socket; no new dependencies."""

    def __init__(self, socket_path: Path, timeout: float) -> None:
        super().__init__("installer", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(str(self._socket_path))
        self.sock = sock


def _daemon_request(
    method: str,
    path: str,
    token: str,
    body: dict[str, object] | None = None,
    *,
    timeout: float = 120,
) -> tuple[int, str]:
    """One authenticated request against the daemon's Unix socket. The
    daemon requires exactly one X-Kyth-Session-Token header matching the
    session token file. Connection failures are retried briefly (the
    daemon may still be binding its socket after a restart); transport
    exhaustion raises RuntimeError, which main() routes through fail()."""
    payload = json.dumps(body) if body is not None else None
    last_error: OSError | None = None
    for _ in range(10):
        connection = _UnixHTTPConnection(INSTALLER_SOCKET, timeout)
        try:
            connection.request(
                method,
                path,
                body=payload,
                headers={
                    "X-Kyth-Session-Token": token,
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8", "replace")
        except OSError as exc:
            last_error = exc
            time.sleep(1)
        finally:
            connection.close()
    raise RuntimeError(f"installer daemon socket is unavailable: {last_error}")


def _daemon_stream_terminal_state(
    token: str, *, budget: float = DAEMON_STREAM_BUDGET_SECONDS
) -> str:
    """Follow GET /api/stream until the daemon closes it after a
    terminal (done/error) job event. Returns the last event payload
    seen; an error event or a blown budget raises RuntimeError carrying
    the last state, which main() routes through fail()."""
    sock: socket.socket | None = None
    last_error: OSError | None = None
    for _ in range(10):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect(str(INSTALLER_SOCKET))
            break
        except OSError as exc:
            last_error = exc
            if sock is not None:
                sock.close()
                sock = None
            time.sleep(1)
    if sock is None:
        raise RuntimeError(f"installer daemon socket is unavailable: {last_error}")
    try:
        request = (
            "GET /api/stream HTTP/1.1\r\nHost: installer\r\n"
            f"X-Kyth-Session-Token: {token}\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(request.encode("utf-8"))
        stream = sock.makefile("rb")
        status_line = stream.readline(64 * 1024).decode("utf-8", "replace")
        parts = status_line.split()
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if status != 200:
            raise RuntimeError(f"installer event stream answered HTTP {status}")
        while stream.readline(64 * 1024) not in (b"\r\n", b"\n", b""):
            pass
        deadline = time.monotonic() + budget
        last_state = ""
        while True:
            try:
                line = stream.readline(64 * 1024)
            except (socket.timeout, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"installer job did not finish within {int(budget)}s; "
                        f"last event: {last_state}"
                    ) from None
                continue
            if not line:
                return last_state
            text = line.decode("utf-8", "replace").strip()
            if not text.startswith("data:"):
                continue
            payload = text.partition(":")[2].strip()
            if not payload:
                continue
            last_state = payload[:512]
            try:
                event = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                if event.get("type") == "done":
                    return last_state
                if event.get("type") == "error":
                    message = event.get("message")
                    if not isinstance(message, str) or not message:
                        message = "installer reported an error"
                    raise RuntimeError(f"installer job failed: {message}")
    finally:
        sock.close()


def _prepare_installer_daemon() -> tuple[str, object]:
    """Replicate kyth-launch-installer's daemon preparation without the
    GUI shell: the runtime directory (0750 root:liveuser), the session
    lock, a fresh root-owned 0600 session token (the daemon's
    read_session_token requires uid 0 and no group/other access), and a
    daemon restart so it picks the new token up. The launcher's
    client-<uid>/tokens.json sidecar exists only for the GUI shell and
    has no headless equivalent. Returns (token, lock handle); the caller
    keeps the handle alive for the session's lifetime."""
    try:
        lock_handle = INSTALLER_LOCK_FILE.open("a+")
    except OSError as exc:
        raise RuntimeError(f"could not open installer session lock: {exc}") from exc
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        lock_handle.close()
        raise RuntimeError(
            "another installer session is already in progress"
        ) from exc
    created = run(
        [
            "install", "-d", "-m", "0750", "-o", "root", "-g", "liveuser",
            str(INSTALLER_RUN_DIR),
        ],
        timeout=120,
    )
    if created.returncode:
        raise RuntimeError("could not create the installer runtime directory")
    result = run_text(["openssl", "rand", "-hex", "32"], timeout=30)
    if result is None or result.returncode:
        raise RuntimeError("could not generate an installer session token")
    token = result.stdout.strip()
    if len(token) != 64 or any(char not in "0123456789abcdef" for char in token):
        raise RuntimeError("openssl produced an unexpected session token")
    temporary = INSTALLER_TOKEN_FILE.with_name(
        f"{INSTALLER_TOKEN_FILE.name}.{os.getpid()}"
    )
    temporary.write_text(token, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, INSTALLER_TOKEN_FILE)
    restarted = run(["systemctl", "restart", "kyth-installerd.service"], timeout=120)
    if restarted.returncode:
        raise RuntimeError("could not restart the installer daemon")
    for _ in range(30):
        active = run_text(
            ["systemctl", "is-active", "--quiet", "kyth-installerd.service"],
            timeout=5,
        )
        if (
            active is not None
            and active.returncode == 0
            and INSTALLER_SOCKET.exists()
        ):
            return token, lock_handle
        time.sleep(1)
    raise RuntimeError("installer daemon did not become ready")


def install_via_installer_daemon() -> None:
    """Daemon-driven install: same live prelude and completion contract
    as the raw bootc path (LIVE_READY, INSTALL_STARTED, INSTALL_COMPLETE,
    reboot into the installed lifecycle), but the install itself is the
    real kyth-installerd job a user session would start."""
    if not wait_for_desktop("live"):
        fail("live Plasma desktop did not become ready")
    emit("LIVE_READY", "plasmashell-active")
    run_smoke_check("LIVE")
    for _ in range(60):
        if TARGET_BY_ID.is_block_device():
            break
        time.sleep(1)
    try:
        target = TARGET_BY_ID.resolve(strict=True)
    except OSError:
        fail("dedicated acceptance disk not found")
    if not target.is_block_device():
        fail("acceptance disk symlink did not resolve to a block device")
    # The daemon takes its source from KYTH_SOURCE_IMAGE in its own
    # EnvironmentFile and falls back to a floating tag when the pin is
    # absent; resolve the pin here and fail closed exactly like the raw
    # path does before it passes the pin to bootc.
    source_ref = _installer_source_ref()
    if not valid_update_ref(source_ref):
        fail("installer source image reference contains unsupported characters")
    target_ref = _installer_target_ref()
    token, _lock_handle = _prepare_installer_daemon()
    status, body = _daemon_request("GET", "/api/disks", token)
    if status != 200:
        fail(
            f"installer disk inventory answered HTTP {status}: "
            f"{_daemon_error_message(body)}"
        )
    try:
        inventory = json.loads(body)
    except json.JSONDecodeError as exc:
        fail(f"installer disk inventory was not valid JSON: {exc}")
    disk = _acceptance_disk_from_inventory(inventory, target)
    if disk is None:
        fail(
            f"dedicated acceptance disk {target} is missing from the "
            "installer inventory or hosts the live system"
        )
    # Windows variant: the install is an NTFS shrink of the prepared
    # Windows partition, chosen by the daemon's own candidacy flag.
    # Record the volume identity first so the post-install probe (and
    # the installed lifecycle) can prove the shrink preserved it.
    windows_target: tuple[str, str] | None = None
    if windows_mode():
        status, body = _daemon_request(
            "GET", f"/api/partitions?disk={quote(disk, safe='')}", token
        )
        if status != 200:
            fail(
                f"installer partition inventory answered HTTP {status}: "
                f"{_daemon_error_message(body)}"
            )
        try:
            partitions = json.loads(body)
        except json.JSONDecodeError as exc:
            fail(f"installer partition inventory was not valid JSON: {exc}")
        selected = _windows_resize_target_from_partitions(partitions)
        if selected is None:
            fail(
                "installer inventory offers no NTFS shrink candidate on "
                "the acceptance disk; the prepared Windows partition is "
                "missing or below the 96 GiB candidacy minimum"
            )
        partition, resize_gib = selected
        uuid = next(
            (u for name, u in _ntfs_uuids(str(target)) if name == partition and u),
            "",
        )
        if not uuid:
            fail(f"prepared NTFS partition {partition} has no readable volume UUID")
        emit("WINDOWS_NTFS_BEFORE", f"device={partition} uuid={uuid}")
        windows_target = (partition, uuid)
        request = _daemon_windows_start_request(
            disk,
            ACCEPTANCE_HOSTNAME,
            ACCEPTANCE_USERNAME,
            ACCEPTANCE_PASSWORD,
            partition,
            resize_gib,
        )
    else:
        request = _daemon_start_request(
            disk, ACCEPTANCE_HOSTNAME, ACCEPTANCE_USERNAME, ACCEPTANCE_PASSWORD
        )
    emit("INSTALL_STARTED", str(target))
    status, body = _daemon_request("POST", "/api/start", token, request)
    if status != 200:
        fail(
            f"installer start answered HTTP {status}: "
            f"{_daemon_error_message(body)}"
        )
    _daemon_stream_terminal_state(token)
    status, body = _daemon_request("GET", "/api/report", token)
    if status != 200:
        fail(
            f"installer report answered HTTP {status}: "
            f"{_daemon_error_message(body)}"
        )
    try:
        report = json.loads(body)
    except json.JSONDecodeError as exc:
        fail(f"installer report was not valid JSON: {exc}")
    failures = _report_failures(report)
    if failures:
        fail("installer assurance failed: " + ", ".join(failures))
    if windows_target is not None:
        partition, uuid_before = windows_target
        uuid_after = next(
            (u for name, u in _ntfs_uuids(str(target)) if name == partition),
            "",
        )
        if not uuid_after:
            fail(
                f"NTFS partition {partition} is missing or lost its "
                "volume identity during the alongside install"
            )
        if uuid_after.lower() != uuid_before.lower():
            fail(
                "NTFS volume identity changed during the alongside "
                f"install: {uuid_before} -> {uuid_after}"
            )
        emit("WINDOWS_NTFS_AFTER", f"device={partition} uuid={uuid_after}")
    emit("INSTALL_COMPLETE", target_ref)
    power("reboot")


def _state_value() -> str:
    try:
        return STATE_FILE.read_text(encoding="utf-8").strip() or "fresh"
    except OSError:
        return "fresh"


def _initial_digest() -> str:
    try:
        return (STATE_DIR / "initial-digest").read_text(encoding="utf-8").strip()
    except OSError:
        fail("initial deployment digest is missing")
    return ""


def _logged(command: list[str], error: str) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as log:
        result = run(command, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        fail(error)


def _active_graphical_session() -> tuple[str, dict[str, str]] | None:
    """Return the active desktop user and the minimal environment it needs."""
    active = run_text(["loginctl", "show-seat", "seat0", "-p", "ActiveSession", "--value"], timeout=5)
    session = active.stdout.strip() if active and active.returncode == 0 else ""
    if not session:
        return None
    owner = run_text(["loginctl", "show-session", session, "-p", "Name", "--value"], timeout=5)
    username = owner.stdout.strip() if owner and owner.returncode == 0 else ""
    if not username:
        return None
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        return None
    runtime = Path(f"/run/user/{account.pw_uid}")
    wayland = next(iter(sorted(runtime.glob("wayland-*"))), None)
    x11 = next(iter(sorted(Path("/tmp/.X11-unix").glob("X*"))), None)
    environment = {
        "HOME": account.pw_dir,
        "LOGNAME": username,
        "USER": username,
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "XDG_RUNTIME_DIR": str(runtime),
        "XDG_CURRENT_DESKTOP": "KDE",
        "XDG_SESSION_TYPE": "wayland" if wayland else "x11" if x11 else "",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }
    if wayland:
        environment["WAYLAND_DISPLAY"] = wayland.name
    if x11:
        environment["DISPLAY"] = f":{x11.name.removeprefix('X')}"
    xauthority = Path(account.pw_dir) / ".Xauthority"
    if xauthority.is_file():
        environment["XAUTHORITY"] = str(xauthority)
    return username, environment


def _hub_pages() -> tuple[tuple[str, str], ...]:
    try:
        manifest = json.loads(HUB_ROUTE_MANIFEST.read_text(encoding="utf-8"))
        pages: list[tuple[str, str]] = [("Welcome", "/")]
        for destination in manifest["destinations"]:
            route = str(destination["route"])
            key = str(destination["key"])
            pages.append((key, route))
            pages.extend(
                (str(section["key"]), f"{route}?section={quote(str(section['key']), safe='')}" )
                for section in destination["sections"]
            )
        if len({key for key, _ in pages}) != len(pages):
            raise ValueError("Hub route manifest contains duplicate page keys")
        return tuple(pages)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        fail(f"Hub route manifest could not be read: {exc}")
    return ()


def _hub_start(username: str, environment: dict[str, str], page: str, evidence: Path, *, degraded: bool = False) -> subprocess.Popen[bytes]:
    values = dict(environment)
    values["KYTH_HUB_ACCEPTANCE_FILE"] = str(evidence)
    if degraded:
        values["KYTH_HUB_ACCEPTANCE_DEGRADED"] = "1"
    command = [
        "runuser", "-u", username, "--", "env",
        *(f"{key}={value}" for key, value in values.items() if value),
        str(HUB_BINARY), "--page", page,
    ]
    stream = evidence.with_suffix(".process.log").open("ab")
    try:
        return subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
    finally:
        stream.close()


def _hub_stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=8)


def _hub_event(evidence: Path, event: str) -> dict[str, object] | None:
    prefix = f"KYTH_HUB_ACCEPTANCE:{event}:"
    try:
        lines = evidence.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        if line.startswith(prefix):
            try:
                value = json.loads(line.removeprefix(prefix))
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _wait_hub_event(evidence: Path, event: str, *, timeout: int = HUB_ACCEPTANCE_TIMEOUT) -> dict[str, object] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = _hub_event(evidence, event)
        if value is not None:
            return value
        time.sleep(0.5)
    return None


def _hub_launch_check(username: str, environment: dict[str, str], page: str, expected_route: str, evidence: Path) -> bool:
    evidence.unlink(missing_ok=True)
    try:
        process = _hub_start(username, environment, page, evidence)
    except OSError:
        return False
    try:
        event = _wait_hub_event(evidence, "deep-link")
        return bool(
            event
            and event.get("page") == page
            and event.get("route") == expected_route
            and event.get("source") == "initial"
        )
    finally:
        _hub_stop(process)


def _ensure_acceptance_graphical_session() -> tuple[str, dict[str, str]] | None:
    """Create a disposable desktop account when the installed image has none.

    The live image's ``liveuser`` is created by livesys at runtime and is not
    part of the installed bootc image. The normal installed system therefore
    correctly stops at the login manager until a user is created, but that
    leaves the firmware-gated VM acceptance service without a graphical
    session in which to exercise the installed Hub. Create an acceptance-only
    account and restart the login manager; this path is reachable only when
    QEMU exposes the acceptance fw_cfg flag.
    """
    session = _active_graphical_session()
    if session and (session[1].get("WAYLAND_DISPLAY") or session[1].get("DISPLAY")):
        return session

    username = "kyth-acceptance"
    account = run_text(["id", "-u", username], timeout=5)
    if account is None or account.returncode:
        created = run(["useradd", "--create-home", "--shell", "/bin/bash", username], timeout=30)
        if created.returncode:
            return None
    try:
        config = Path("/etc/plasmalogin.conf.d/90-kyth-vm-acceptance.conf")
        config.write_text(
            "[Autologin]\nUser=kyth-acceptance\nSession=plasma.desktop\nRelogin=true\n",
            encoding="utf-8",
        )
    except OSError:
        return None
    restarted = run(["systemctl", "restart", "display-manager.service", "--no-block"], timeout=30)
    if restarted.returncode:
        return None
    for _ in range(60):
        session = _active_graphical_session()
        if session and (session[1].get("WAYLAND_DISPLAY") or session[1].get("DISPLAY")):
            return session
        time.sleep(1)
    return None


def run_hub_acceptance() -> None:
    """Exercise the installed Rust/Tauri shell from the installed desktop."""
    if not HUB_BINARY.is_file() or not os.access(HUB_BINARY, os.X_OK):
        fail(f"installed Rust/Tauri Hub binary is missing or not executable: {HUB_BINARY}")
    session = _ensure_acceptance_graphical_session()
    if session is None:
        fail("active graphical session for installed Hub acceptance was not found")
    username, environment = session
    evidence = Path(f"/tmp/kyth-hub-acceptance-{os.getuid()}.log")
    emit("HUB_BINARY_OK", str(HUB_BINARY))

    pages = _hub_pages()
    for page, route in pages:
        if not _hub_launch_check(username, environment, page, route, evidence):
            fail(f"Hub --page deep link failed for {page!r}")
    emit(
        "HUB_DEEP_LINKS_OK",
        "; ".join(f"{page}={route}" for page, route in pages),
    )

    evidence.unlink(missing_ok=True)
    first = _hub_start(username, environment, "Welcome", evidence)
    try:
        if _wait_hub_event(evidence, "deep-link") is None:
            fail("Hub first launch did not resolve Welcome")
        evidence.unlink(missing_ok=True)
        second = _hub_start(username, environment, "Updates", evidence)
        try:
            forwarded = _wait_hub_event(evidence, "deep-link")
            if not forwarded or forwarded.get("page") != "Updates" or forwarded.get("source") != "single-instance":
                fail("Hub second launch did not forward the Updates page")
        finally:
            _hub_stop(second)
    finally:
        _hub_stop(first)
    emit("HUB_SECOND_LAUNCH_OK", "Updates forwarded to the existing Hub process")

    evidence.unlink(missing_ok=True)
    degraded = _hub_start(username, environment, "Welcome", evidence, degraded=True)
    try:
        dashboard = _wait_hub_event(evidence, "dashboard")
        if not dashboard or dashboard.get("state") != "degraded" or dashboard.get("label") != "Status unavailable":
            fail("Hub dashboard did not report its unavailable-data state honestly")
    finally:
        _hub_stop(degraded)
    emit("HUB_DASHBOARD_DEGRADED_OK", "Status unavailable")

    evidence.unlink(missing_ok=True)
    updates = _hub_start(username, environment, "Updates", evidence)
    try:
        update_probe = _wait_hub_event(evidence, "updates-probe")
        privilege_probe = _wait_hub_event(evidence, "privileged-failure")
        if not update_probe or update_probe.get("state") not in {"ok", "degraded"}:
            fail("Hub Updates page did not report a usable or degraded probe result")
        if not privilege_probe or privilege_probe.get("state") != "expected":
            fail("Hub privileged-action failure was not surfaced as an expected failure")
    finally:
        _hub_stop(updates)
    emit("HUB_UPDATES_OK", str(update_probe.get("state", "unknown")))
    emit("HUB_PRIVILEGED_FAILURE_OK", "allowlist rejection surfaced")


def run_installed_lifecycle() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = _state_value()
    update_ref = read_update_ref()
    if not valid_update_ref(update_ref):
        fail("update image reference contains unsupported characters")
    if not wait_for_desktop("installed"):
        fail("installed display manager did not become ready")
    if state == "fresh":
        emit("INSTALLED_READY", "display-manager-active")
        _selinux_enforcing()
        _first_boot_check()
        if secure_boot_mode():
            _secure_boot_check()
        if windows_mode():
            _windows_ntfs_check()
        if network_check_enabled():
            _network_check()
        run_smoke_check("INSTALLED")
        run_hub_acceptance()
        initial = booted_digest()
        if not initial:
            fail("could not read initial booted digest")
        _atomic_write(STATE_DIR / "initial-digest", initial + "\n")
        if not update_ref:
            emit("COMPLETE", "install-only")
            power("poweroff")
            return
        _atomic_write(STATE_FILE, "update-staged\n")
        emit("UPDATE_STARTED", update_ref)
        _logged(["bootc", "switch", update_ref], "bootc switch failed")
        emit("UPDATE_STAGED", update_ref)
        power("reboot")
    elif state == "update-staged":
        initial, current = _initial_digest(), booted_digest()
        if not current or current == initial:
            fail("updated deployment did not boot a different digest")
        if deployment_count() < 2:
            fail("updated system does not expose a rollback deployment")
        emit("UPDATE_BOOTED", current)
        run_smoke_check("UPDATE")
        _atomic_write(STATE_FILE, "rollback-staged\n")
        _logged(["bootc", "rollback"], "bootc rollback failed")
        emit("ROLLBACK_STAGED", initial)
        power("reboot")
    elif state == "rollback-staged":
        initial, current = _initial_digest(), booted_digest()
        if not current or current != initial:
            fail("rollback did not restore the initial deployment digest")
        emit("ROLLBACK_BOOTED", current)
        run_smoke_check("ROLLBACK")
        emit("COMPLETE", "update-and-rollback")
        STATE_FILE.unlink(missing_ok=True)
        power("poweroff")
    else:
        fail(f"unknown acceptance state: {state}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("enabled", "run"))
    args = parser.parse_args(argv)
    if args.command == "enabled":
        return 0 if enabled() else 1
    if not enabled():
        return 0
    try:
        if INSTALLER_ENV_FILE.is_file():
            if installer_daemon_mode():
                install_via_installer_daemon()
            else:
                install_from_live_iso()
        else:
            run_installed_lifecycle()
    except (OSError, RuntimeError, ValueError) as exc:
        fail(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
