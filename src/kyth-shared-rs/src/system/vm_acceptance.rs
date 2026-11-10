//! Rust-owned VM acceptance guest lifecycle.
//!
//! The source-tree Python module is retained as a parity fixture. The
//! packaged run entry point uses this module so firmware gating, validation,
//! bounded execution, destructive operations, state persistence, and failure
//! reporting have one Rust owner.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::atomic_io::atomic_write_text;
use crate::system::process::{redact_sensitive_text, run_bounded};

const FW_CFG_ROOT: &str = "/sys/firmware/qemu_fw_cfg/by_name/opt/com.kyth";
const STATE_DIR: &str = "/var/lib/kyth/vm-acceptance";
const STATE_FILE: &str = "/var/lib/kyth/vm-acceptance/state";
const INITIAL_DIGEST_FILE: &str = "/var/lib/kyth/vm-acceptance/initial-digest";
const SERIAL_DEVICE: &str = "/dev/ttyS0";
const LOG_FILE: &str = "/var/log/kyth-vm-acceptance.log";
const TARGET_BY_ID: &str = "/dev/disk/by-id/virtio-KYTH_ACCEPT";
const INSTALLER_ENV_FILE: &str = "/etc/kyth-installer.env";
const HUB_BINARY: &str = "/usr/bin/kyth-hub-shell";
const HUB_ROUTE_MANIFEST: &str = "/usr/share/kyth/hubRoutes.json";
const HUB_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(45);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const UPDATE_REF_MAX: usize = 512;

pub fn valid_update_ref(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= UPDATE_REF_MAX
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'/' | b'@' | b':' | b'+' | b'-')
            }))
}

pub fn read_trimmed(path: impl AsRef<Path>) -> String {
    fs::read(path)
        .unwrap_or_default()
        .into_iter()
        .filter(|byte| *byte != 0)
        .map(char::from)
        .collect::<String>()
        .trim()
        .to_owned()
}

pub fn enabled() -> bool {
    read_trimmed(format!("{FW_CFG_ROOT}/acceptance/raw")) == "1"
}

pub fn update_ref() -> String {
    read_trimmed(format!("{FW_CFG_ROOT}/update-ref/raw"))
}

pub fn network_check_enabled() -> bool {
    read_trimmed(format!("{FW_CFG_ROOT}/network-check/raw")) == "1"
}

/// Opt-in (fw_cfg `installer-mode=daemon`) install route: drive the real
/// installer daemon over its authenticated Unix socket instead of the raw
/// bootc path. Off by default so the established raw route stays the
/// default until the daemon route has qualified.
pub fn installer_daemon_mode() -> bool {
    read_trimmed(format!("{FW_CFG_ROOT}/installer-mode/raw")) == "daemon"
}

/// Variant flag (fw_cfg `secure-boot`): the host booted secboot OVMF
/// firmware with the KythOS MOK certificate pre-enrolled, so the
/// installed lifecycle must prove the installed system really reports
/// Secure Boot enabled.
pub fn secure_boot_mode() -> bool {
    read_trimmed(format!("{FW_CFG_ROOT}/secure-boot/raw")) == "1"
}

/// Variant flag (fw_cfg `windows`): the host prepared a Windows side
/// (GPT + ESP + NTFS) on the acceptance disk, so the daemon route must
/// perform an alongside NTFS-shrink install and the installed lifecycle
/// must prove the NTFS volume survived.
pub fn windows_mode() -> bool {
    read_trimmed(format!("{FW_CFG_ROOT}/windows/raw")) == "1"
}

pub fn booted_digest_from_json(output: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(output).ok()?;
    let image = value.get("status")?.get("booted")?.get("image")?;
    image
        .get("imageDigest")
        .and_then(Value::as_str)
        .or_else(|| {
            image
                .get("image")
                .and_then(|nested| nested.get("imageDigest"))
                .and_then(Value::as_str)
        })
        .filter(|digest| !digest.is_empty())
        .map(str::to_owned)
}

pub fn deployment_count_from_json(output: &str) -> usize {
    let Ok(value) = serde_json::from_str::<Value>(output) else {
        return 0;
    };
    match value {
        Value::Array(items) => items.len(),
        Value::Object(object) => object
            .get("deployments")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        _ => 0,
    }
}

pub fn acceptance_state_from_text(value: Option<&str>) -> &str {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("fresh") | None => "fresh",
        Some("update-staged") => "update-staged",
        Some("rollback-staged") => "rollback-staged",
        Some(_) => "unknown",
    }
}

pub fn acceptance_event(phase: &str, detail: &str) -> String {
    format!("KYTH_ACCEPTANCE:{phase}:{}", detail.replace('\n', " "))
}

fn emit(phase: &str, detail: impl AsRef<str>) {
    let line = redact_sensitive_text(&acceptance_event(phase, detail.as_ref()));
    println!("{line}");
    if let Ok(mut log) = OpenOptions::new().create(true).append(true).open(LOG_FILE) {
        let _ = writeln!(log, "{line}");
    }
    if let Ok(mut serial) = OpenOptions::new().write(true).open(SERIAL_DEVICE) {
        let _ = writeln!(serial, "{line}");
    }
}

fn power(action: &str) {
    let _ = run_bounded(
        &["systemctl".into(), action.into(), "--no-block".into()],
        Duration::from_secs(30),
    );
}

fn log_output(output: &Output) {
    let text = redact_sensitive_text(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    if !text.is_empty() {
        if let Ok(mut log) = OpenOptions::new().create(true).append(true).open(LOG_FILE) {
            let _ = writeln!(log, "{text}");
        }
    }
}

fn run_logged(argv: &[String], timeout: Duration, failure: &str) -> io::Result<Output> {
    let output = run_bounded(argv, timeout)
        .map_err(|error| io::Error::new(error.kind(), format!("{failure}: {error}")))?;
    log_output(&output);
    output
        .status
        .success()
        .then_some(output)
        .ok_or_else(|| io::Error::other(failure))
}

fn wait_for_desktop(mode: &str) -> bool {
    for _ in 0..90 {
        let argv = if mode == "live" {
            vec!["pgrep".into(), "-x".into(), "plasmashell".into()]
        } else {
            vec![
                "systemctl".into(),
                "is-active".into(),
                "--quiet".into(),
                "display-manager.service".into(),
            ]
        };
        if run_bounded(&argv, Duration::from_secs(5)).is_ok_and(|output| output.status.success()) {
            return true;
        }
        thread::sleep(Duration::from_secs(2));
    }
    false
}

fn booted_digest() -> String {
    run_bounded(
        &[
            "bootc".into(),
            "status".into(),
            "--format".into(),
            "json".into(),
        ],
        Duration::from_secs(30),
    )
    .ok()
    .filter(|output| output.status.success())
    .and_then(|output| booted_digest_from_json(&String::from_utf8_lossy(&output.stdout)))
    .unwrap_or_default()
}

fn deployment_count() -> usize {
    run_bounded(
        &[
            "ostree".into(),
            "admin".into(),
            "status".into(),
            "--json".into(),
        ],
        Duration::from_secs(30),
    )
    .ok()
    .filter(|output| output.status.success())
    .map(|output| deployment_count_from_json(&String::from_utf8_lossy(&output.stdout)))
    .unwrap_or(0)
}

fn smoke_check(phase: &str) -> io::Result<()> {
    let output = run_logged(
        &["/usr/bin/kyth-smoke-check".into(), "--verbose".into()],
        Duration::from_secs(300),
        &format!("{phase} smoke check failed"),
    )?;
    if let Ok(data) = fs::read(LOG_FILE) {
        if let Ok(mut serial) = OpenOptions::new().write(true).open(SERIAL_DEVICE) {
            let _ = serial.write_all(&data);
        }
    }
    if output.status.code().unwrap_or(1) >= 2 {
        return Err(io::Error::other(format!(
            "{phase} smoke check reported failed invariants"
        )));
    }
    emit(
        &format!("{phase}_SMOKE_OK"),
        format!("warnings-allowed={}", output.status.code().unwrap_or(0)),
    );
    Ok(())
}

/// The installed system must boot with SELinux Enforcing. The live ISO
/// boots permissive so the install itself is not blocked by labelling,
/// and nothing else asserts the installed deployment did not stay that
/// way.
fn selinux_enforcing() -> io::Result<()> {
    let output = run_bounded(&["getenforce".into()], Duration::from_secs(10));
    let mode = output
        .as_ref()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default();
    if output.is_ok_and(|output| output.status.success()) && mode == "Enforcing" {
        emit("INSTALLED_SELINUX_OK", "Enforcing");
        return Ok(());
    }
    Err(io::Error::other(format!(
        "installed system reports SELinux mode {mode:?}, expected Enforcing"
    )))
}

/// Pure parse of `systemctl --failed --no-legend` output: one unit name
/// per non-empty line. systemd prefixes failed units with a bullet that
/// `--no-legend` does not suppress on every version, so strip it.
pub fn failed_units_from_output(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            line.trim()
                .trim_start_matches('●')
                .trim()
                .split_whitespace()
                .next()
                .map(str::to_owned)
        })
        .collect()
}

/// First-boot completion truth: the smoke check samples individual
/// invariants, but a boot that left units failed or never completed the
/// hardware-setup oneshot is not a finished first boot.
fn first_boot_check() -> io::Result<()> {
    let output = run_bounded(
        &["systemctl".into(), "--failed".into(), "--no-legend".into()],
        Duration::from_secs(30),
    )?;
    if !output.status.success() {
        return Err(io::Error::other("systemctl --failed did not complete"));
    }
    let failed = failed_units_from_output(&String::from_utf8_lossy(&output.stdout));
    if !failed.is_empty() {
        return Err(io::Error::other(format!(
            "installed system has {} failed unit(s): {}",
            failed.len(),
            failed.join(", ")
        )));
    }
    let result = run_bounded(
        &[
            "systemctl".into(),
            "show".into(),
            "-p".into(),
            "Result".into(),
            "--value".into(),
            "kyth-hw-setup.service".into(),
        ],
        Duration::from_secs(10),
    )?;
    let value = String::from_utf8_lossy(&result.stdout).trim().to_owned();
    if !result.status.success() || value != "success" {
        return Err(io::Error::other(format!(
            "kyth-hw-setup.service finished with Result={value:?}, expected \"success\""
        )));
    }
    emit("FIRSTBOOT_OK", failed.len().to_string());
    Ok(())
}

/// Registry host portion of an image reference (everything before the
/// first path separator).
pub fn registry_host(reference: &str) -> String {
    reference.split('/').next().unwrap_or_default().to_owned()
}

/// Opt-in (fw_cfg `network-check`) registry reachability truth: the
/// update path is only real if the installed system can resolve and
/// reach the registry it would pull from. Off by default so hermetic
/// runs without outbound networking do not false-fail.
fn network_check() -> io::Result<()> {
    let host = registry_host(&installer_target_ref());
    let resolved = run_bounded(
        &["getent".into(), "hosts".into(), host.clone()],
        Duration::from_secs(10),
    );
    if !resolved.is_ok_and(|output| output.status.success()) {
        return Err(io::Error::other(format!(
            "registry host {host} did not resolve"
        )));
    }
    let probe = run_bounded(
        &[
            "curl".into(),
            "-fsS".into(),
            "-o".into(),
            "/dev/null".into(),
            "-w".into(),
            "%{http_code}".into(),
            "--max-time".into(),
            "30".into(),
            format!("https://{host}/v2/"),
        ],
        Duration::from_secs(40),
    )?;
    let code_text = String::from_utf8_lossy(&probe.stdout).trim().to_owned();
    let code = code_text.parse::<u32>().unwrap_or(0);
    if !(100..500).contains(&code) {
        return Err(io::Error::other(format!(
            "registry {host} answered HTTP {code_text:?}, expected a status below 500"
        )));
    }
    emit("INSTALLED_NETWORK_OK", code.to_string());
    Ok(())
}

fn installer_target_ref() -> String {
    fs::read_to_string(INSTALLER_ENV_FILE)
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("KYTH_TARGET_IMAGE=")
                    .map(|value| value.trim().trim_matches(['\'', '"']).to_owned())
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "ghcr.io/mrtrickdotorg/kyth:testing".into())
}

/// Pure parse of the digest-pinned source image the live image was built
/// with (`KYTH_SOURCE_IMAGE` in the installer env file). Kept separate
/// from the file read so the parse is unit-testable, mirroring
/// `booted_digest_from_json`.
pub fn source_ref_from_env(contents: &str) -> Option<String> {
    contents
        .lines()
        .find_map(|line| {
            line.strip_prefix("KYTH_SOURCE_IMAGE=")
                .map(|value| value.trim().trim_matches(['\'', '"']).to_owned())
        })
        .filter(|value| !value.is_empty())
}

/// The install source must come from the pin the image build wrote,
/// never from a hardcoded registry reference: a floating tag could
/// resolve to a different image than the one the live media was built
/// and signed for. Fail closed when the pin is absent (the Python parity
/// fixture pins this exact error message).
fn installer_source_ref() -> io::Result<String> {
    fs::read_to_string(INSTALLER_ENV_FILE)
        .ok()
        .and_then(|contents| source_ref_from_env(&contents))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "pinned installer source is missing from live image",
            )
        })
}

#[cfg(unix)]
fn is_block_device(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_block_device())
}

fn install_from_live_iso() -> io::Result<()> {
    if !wait_for_desktop("live") {
        return Err(io::Error::other("live Plasma desktop did not become ready"));
    }
    emit("LIVE_READY", "plasmashell-active");
    smoke_check("LIVE")?;
    let target = Path::new(TARGET_BY_ID).canonicalize().map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "dedicated acceptance disk not found",
        )
    })?;
    if !is_block_device(&target) {
        return Err(io::Error::other(
            "acceptance disk symlink did not resolve to a block device",
        ));
    }
    if !Path::new("/usr/share/kyth/image").is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "bundled OCI image is missing from live media",
        ));
    }
    let reference = update_ref();
    if !valid_update_ref(&reference) {
        return Err(io::Error::other(
            "update image reference contains unsupported characters",
        ));
    }
    let target_ref = installer_target_ref();
    let source_ref = installer_source_ref()?;
    if !valid_update_ref(&source_ref) {
        return Err(io::Error::other(
            "installer source image reference contains unsupported characters",
        ));
    }
    emit("INSTALL_STARTED", target.display().to_string());
    run_logged(
        &[
            "bootc".into(),
            "install".into(),
            "to-disk".into(),
            "--source-imgref".into(),
            source_ref,
            "--target-imgref".into(),
            target_ref.clone(),
            "--filesystem".into(),
            "btrfs".into(),
            "--wipe".into(),
            "--skip-fetch-check".into(),
            target.display().to_string(),
        ],
        Duration::from_secs(1800),
        "bootc install to-disk failed",
    )?;
    emit("INSTALL_COMPLETE", target_ref);
    power("reboot");
    Ok(())
}

const INSTALLER_RUN_DIR: &str = "/run/kyth-installer";
const INSTALLER_SOCKET_PATH: &str = "/run/kyth-installer/api.sock";
const INSTALLER_TOKEN_FILE: &str = "/run/kyth-installer/session-token";
const INSTALLER_LOCK_FILE: &str = "/run/lock/kyth-installer.lock";
const ACCEPTANCE_HOSTNAME: &str = "kyth-acceptance";
const ACCEPTANCE_USERNAME: &str = "kyth-acceptance";
/// Throwaway password for the throwaway acceptance account on a VM that
/// is discarded after the run; it exists only because the daemon requires
/// a non-empty login password at its API boundary
/// (validate_start_acknowledgements in installer_daemon.rs).
const ACCEPTANCE_PASSWORD: &str = "kyth-acceptance";
/// The stream wait must leave headroom inside the guest unit's 1800s
/// TimeoutStartSec for the daemon preparation and report evaluation.
const DAEMON_STREAM_BUDGET: Duration = Duration::from_secs(1500);
/// Assurance check names emitted by installer_assurance::validate
/// (installer_assurance.rs). The daemon's report mixes these with other
/// progress checks (power, boot_entries); only the assurance set is
/// required to be present and passing.
const ASSURANCE_CHECK_NAMES: [&str; 10] = [
    "hostname",
    "locale",
    "keymap",
    "timezone",
    "account",
    "filesystem",
    "selinux",
    "encryption",
    "kernel",
    "bootloader",
];

/// The /api/start body for a wipe install, mirroring the web frontend's
/// InstallRequest field set (src/kyth-installer-web/src/types.ts) and the
/// values native_request_from_start + validate_start_acknowledgements
/// require (installer_daemon.rs): the erase/backup confirmations and the
/// irreversible acknowledgement must all be true, and a login username
/// and password must be present. `encryption` stays "none" (the
/// from_http default in installer_job_executor.rs): acceptance exercises
/// the install route, not a LUKS variant. The image source is NOT a
/// request field — the daemon reads KYTH_SOURCE_IMAGE from its own
/// EnvironmentFile — so the caller fail-closes on the pin separately via
/// installer_source_ref().
pub fn daemon_start_request(disk: &str, hostname: &str, username: &str, password: &str) -> Value {
    serde_json::json!({
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
        "confirm_backup": true,
        "confirm_erase": true,
        "confirm_current": false,
        "encryption": "none",
        "tpm_recovery_ack": false,
        "acknowledged_irreversible": true,
        "flatpaks": [],
    })
}

/// The smallest NTFS partition the installer offers as a shrink
/// candidate (installer_storage.rs: NTFS_MIN_BYTES = 64 GiB Windows
/// floor + 32 GiB KythOS minimum, the latter also installer_plan.rs
/// MIN_KYTHOS_GIB). The host's --windows variant sizes its disk so the
/// prepared NTFS partition clears this bar.
const NTFS_RESIZE_MIN_BYTES: u64 = (64 + 32) * 1024 * 1024 * 1024;
/// The Windows side keeps at least this much room in a shrink install;
/// KythOS takes the rest (see NTFS_RESIZE_MIN_BYTES).
const WINDOWS_FLOOR_GIB: u64 = 64;

/// How many GiB KythOS takes when shrinking an NTFS partition of
/// `size_bytes`: everything above the Windows floor, or None when the
/// partition is below the installer's own candidacy minimum (so the
/// result always satisfies MIN_KYTHOS_GIB = 32).
pub fn windows_resize_gib(size_bytes: u64) -> Option<u64> {
    if size_bytes < NTFS_RESIZE_MIN_BYTES {
        return None;
    }
    Some(size_bytes / (1024 * 1024 * 1024) - WINDOWS_FLOOR_GIB)
}

/// Pick the NTFS shrink target out of the daemon's /api/partitions
/// inventory for the acceptance disk: the record the installer itself
/// flags `ntfs_resize_candidate` (the same candidacy the web UI offers),
/// paired with the computed shrink size.
pub fn windows_resize_target_from_partitions(partitions: &Value) -> Option<(String, u64)> {
    partitions.as_array()?.iter().find_map(|partition| {
        if partition
            .get("ntfs_resize_candidate")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return None;
        }
        let name = partition.get("name").and_then(Value::as_str)?;
        let size = partition.get("size_bytes").and_then(Value::as_u64)?;
        windows_resize_gib(size).map(|gib| (name.to_owned(), gib))
    })
}

/// The /api/start body for the --windows variant: identical field set
/// to daemon_start_request, but an NTFS shrink (alongside) install of
/// the prepared Windows partition. The erase confirmation stays true:
/// validate_start_acknowledgements requires it for every mode, and the
/// shrink is destructive to the partition layout even though the NTFS
/// volume itself is preserved.
pub fn daemon_windows_start_request(
    disk: &str,
    hostname: &str,
    username: &str,
    password: &str,
    resize_partition: &str,
    resize_gib: u64,
) -> Value {
    let mut request = daemon_start_request(disk, hostname, username, password);
    request["install_mode"] = "resize_ntfs".into();
    request["resize_partition"] = resize_partition.into();
    request["resize_gib"] = resize_gib.into();
    request
}

/// Pure parse of `lsblk -npro NAME,FSTYPE,UUID` output into the NTFS
/// rows: (device, volume UUID). The NTFS volume UUID (its serial) is
/// the identity the alongside assertions compare before/after — an
/// ntfsresize shrink does not change it, so a changed or missing UUID
/// means the volume did not survive.
pub fn ntfs_entries_from_lsblk(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let fstype = fields.next()?;
            if !fstype.eq_ignore_ascii_case("ntfs") && !fstype.eq_ignore_ascii_case("ntfs3") {
                return None;
            }
            let uuid = fields.next().unwrap_or_default().to_owned();
            Some((name.to_owned(), uuid))
        })
        .collect()
}

/// Pure parse of `mokutil --sb-state` output ("SecureBoot enabled" /
/// "SecureBoot disabled"). None when the state cannot be determined.
pub fn secure_boot_state_from_output(output: &str) -> Option<bool> {
    for line in output.lines() {
        let Some(state) = line.trim().strip_prefix("SecureBoot") else {
            continue;
        };
        let state = state.trim().to_ascii_lowercase();
        if state.starts_with("enabled") {
            return Some(true);
        }
        if state.starts_with("disabled") {
            return Some(false);
        }
    }
    None
}

/// NTFS volumes visible on one device (or every device when `device`
/// is None), as (device, UUID) pairs.
fn ntfs_uuids(device: Option<&str>) -> Vec<(String, String)> {
    let mut argv = vec![
        "lsblk".to_owned(),
        "-npro".to_owned(),
        "NAME,FSTYPE,UUID".to_owned(),
    ];
    if let Some(device) = device {
        argv.push(device.to_owned());
    }
    run_bounded(&argv, Duration::from_secs(30))
        .ok()
        .filter(|output| output.status.success())
        .map(|output| ntfs_entries_from_lsblk(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

/// Secure Boot variant truth: the installed system must report Secure
/// Boot enabled — the variant boots secboot firmware with the KythOS
/// MOK pre-enrolled, so a disabled or unreadable state means the
/// signed boot chain did not engage.
fn secure_boot_check() -> io::Result<()> {
    let output = run_bounded(
        &["mokutil".into(), "--sb-state".into()],
        Duration::from_secs(10),
    )?;
    if !output.status.success() {
        return Err(io::Error::other("mokutil --sb-state did not complete"));
    }
    match secure_boot_state_from_output(&String::from_utf8_lossy(&output.stdout)) {
        Some(true) => {
            emit("INSTALLED_SECUREBOOT_OK", "enabled");
            Ok(())
        }
        Some(false) => Err(io::Error::other(
            "installed system reports Secure Boot disabled",
        )),
        None => Err(io::Error::other(
            "could not determine the installed Secure Boot state from mokutil output",
        )),
    }
}

/// Windows variant truth for the installed lifecycle: an NTFS volume
/// with a readable UUID must still exist after the alongside install
/// and the reboot into the installed system.
fn windows_ntfs_survived() -> io::Result<()> {
    match ntfs_uuids(None)
        .into_iter()
        .find(|(_, uuid)| !uuid.is_empty())
    {
        Some((device, uuid)) => {
            emit("WINDOWS_NTFS_OK", format!("device={device} uuid={uuid}"));
            Ok(())
        }
        None => Err(io::Error::other(
            "no NTFS partition with a volume UUID survived the alongside install",
        )),
    }
}

/// Pick the dedicated acceptance disk out of the daemon's /api/disks
/// inventory. The raw path identifies the target by resolving
/// /dev/disk/by-id/virtio-KYTH_ACCEPT (the QEMU serial the host wrapper
/// assigns); the daemon inventory carries no serial, so the resolved
/// device path is matched against each record's `name` instead. A record
/// flagged `current` hosts the live system and is never eligible.
pub fn acceptance_disk_from_inventory(inventory: &Value, target: &Path) -> Option<String> {
    let target = target.display().to_string();
    inventory.as_array()?.iter().find_map(|disk| {
        let name = disk.get("name").and_then(Value::as_str)?;
        if name != target || disk.get("current").and_then(Value::as_bool) == Some(true) {
            return None;
        }
        Some(name.to_owned())
    })
}

/// Evaluate a /api/report body: the failure list is empty only when the
/// job completed and every assurance check is present and passing.
/// Non-assurance progress checks fail the run only on an explicit
/// "fail" status — the daemon legitimately records "warning" entries
/// (e.g. boot_entries) on successful installs.
pub fn report_failures(report: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    if let Some(status) = report.get("status").and_then(Value::as_str) {
        if status != "complete" {
            failures.push(format!("installer job status is {status:?}"));
        }
    }
    let Some(checks) = report
        .get("checks")
        .and_then(Value::as_array)
        .filter(|checks| !checks.is_empty())
    else {
        failures.push("installer report carries no checks".to_string());
        return failures;
    };
    for name in ASSURANCE_CHECK_NAMES {
        match checks
            .iter()
            .find(|check| check.get("name").and_then(Value::as_str) == Some(name))
        {
            Some(check) => {
                if check.get("status").and_then(Value::as_str) != Some("pass") {
                    failures.push(format!("assurance check {name} did not pass"));
                }
            }
            None => failures.push(format!("assurance check {name} is missing")),
        }
    }
    for check in checks {
        let name = check
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if check.get("status").and_then(Value::as_str) == Some("fail")
            && !ASSURANCE_CHECK_NAMES.contains(&name)
        {
            failures.push(format!("installer check {name} failed"));
        }
    }
    failures
}

/// Best-effort extraction of the daemon's error message from a response
/// body ({"message": ...} or {"error": ...}); falls back to the raw body.
pub fn daemon_error_message(body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        for key in ["message", "error"] {
            if let Some(message) = value.get(key).and_then(Value::as_str) {
                return message.to_owned();
            }
        }
    }
    body.chars().take(512).collect()
}

fn daemon_connect() -> io::Result<UnixStream> {
    let mut last_error = None;
    for _ in 0..10 {
        match UnixStream::connect(INSTALLER_SOCKET_PATH) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("installer daemon socket is unavailable")))
}

/// Read an HTTP/1.1 response head one byte at a time so no body bytes
/// are buffered past the header terminator (the event-stream reader
/// continues on the same socket). Returns the status code and the
/// Content-Length, when the response carries one.
fn read_http_head(reader: &mut impl Read) -> io::Result<(u16, Option<usize>)> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 64 * 1024 {
            return Err(io::Error::other(
                "installer daemon response headers are too large",
            ));
        }
        if reader.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "installer daemon closed the connection",
            ));
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::other(format!(
                "installer daemon sent a malformed status line: {status_line:?}"
            ))
        })?;
    let content_length = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    Ok((status, content_length))
}

/// One authenticated request against the daemon's Unix socket. The
/// daemon requires exactly one X-Kyth-Session-Token header matching the
/// session token file (installer_daemon.rs handle()).
fn daemon_request(
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> io::Result<(u16, String)> {
    let mut stream = daemon_connect()?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let payload = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: installer\r\n\
         X-Kyth-Session-Token: {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    let (status, content_length) = read_http_head(&mut stream)?;
    let mut bytes = Vec::new();
    match content_length {
        Some(length) => {
            bytes.resize(length, 0);
            stream.read_exact(&mut bytes)?;
        }
        None => {
            stream.read_to_end(&mut bytes)?;
        }
    }
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

/// Follow GET /api/stream until the daemon closes it after a terminal
/// (done/error) job event. Returns the last event payload seen; an
/// error event or a blown budget is an Err carrying the last state.
fn daemon_stream_terminal_state(token: &str) -> io::Result<String> {
    let mut stream = daemon_connect()?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let request = format!(
        "GET /api/stream HTTP/1.1\r\nHost: installer\r\n\
         X-Kyth-Session-Token: {token}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let (status, _) = read_http_head(&mut stream)?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "installer event stream answered HTTP {status}"
        )));
    }
    let deadline = Instant::now() + DAEMON_STREAM_BUDGET;
    let mut reader = BufReader::new(stream);
    let mut last_state = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return Ok(last_state),
            Ok(_) => {
                let Some(payload) = line.trim_end().strip_prefix("data:") else {
                    continue;
                };
                let payload = payload.trim();
                if payload.is_empty() {
                    continue;
                }
                last_state = payload.chars().take(512).collect();
                if let Ok(event) = serde_json::from_str::<Value>(payload) {
                    match event.get("type").and_then(Value::as_str) {
                        Some("done") => return Ok(last_state),
                        Some("error") => {
                            let message = event
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("installer reported an error");
                            return Err(io::Error::other(format!(
                                "installer job failed: {message}"
                            )));
                        }
                        _ => {}
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "installer job did not finish within {}s; last event: {last_state}",
                        DAEMON_STREAM_BUDGET.as_secs()
                    )));
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// A prepared daemon session: the token the daemon authenticated
/// against, plus the launcher lock held for the session's lifetime.
struct InstallerDaemonSession {
    token: String,
    _lock: File,
}

/// Replicate kyth-launch-installer's daemon preparation without the
/// GUI shell: the runtime directory (0750 root:liveuser), the session
/// lock, a fresh root-owned 0600 session token (the daemon's
/// read_session_token requires uid 0 and no group/other access), and a
/// daemon restart so it picks the new token up. The launcher's
/// client-<uid>/tokens.json sidecar exists only for the GUI shell and
/// has no headless equivalent.
fn prepare_installer_daemon() -> io::Result<InstallerDaemonSession> {
    use std::os::unix::fs::PermissionsExt;

    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(INSTALLER_LOCK_FILE)?;
    // SAFETY: flock operates on the open file descriptor above; the
    // result is checked before the lock is treated as held.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other(
            "another installer session is already in progress",
        ));
    }
    run_logged(
        &[
            "install".into(),
            "-d".into(),
            "-m".into(),
            "0750".into(),
            "-o".into(),
            "root".into(),
            "-g".into(),
            "liveuser".into(),
            INSTALLER_RUN_DIR.into(),
        ],
        COMMAND_TIMEOUT,
        "could not create the installer runtime directory",
    )?;
    let output = run_logged(
        &["openssl".into(), "rand".into(), "-hex".into(), "32".into()],
        Duration::from_secs(30),
        "could not generate an installer session token",
    )?;
    let token = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::other(
            "openssl produced an unexpected session token",
        ));
    }
    let temporary = format!("{INSTALLER_TOKEN_FILE}.{}", std::process::id());
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(token.as_bytes())?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&temporary, INSTALLER_TOKEN_FILE)?;
    run_logged(
        &[
            "systemctl".into(),
            "restart".into(),
            "kyth-installerd.service".into(),
        ],
        COMMAND_TIMEOUT,
        "could not restart the installer daemon",
    )?;
    for _ in 0..30 {
        let active = run_bounded(
            &[
                "systemctl".into(),
                "is-active".into(),
                "--quiet".into(),
                "kyth-installerd.service".into(),
            ],
            Duration::from_secs(5),
        )
        .is_ok_and(|output| output.status.success());
        if active && Path::new(INSTALLER_SOCKET_PATH).exists() {
            return Ok(InstallerDaemonSession { token, _lock: lock });
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(io::Error::other("installer daemon did not become ready"))
}

/// Daemon-driven install: same live prelude and completion contract as
/// the raw bootc path (LIVE_READY, INSTALL_STARTED, INSTALL_COMPLETE,
/// reboot into the installed lifecycle), but the install itself is the
/// real kyth-installerd job a user session would start.
fn install_via_installer_daemon() -> io::Result<()> {
    if !wait_for_desktop("live") {
        return Err(io::Error::other("live Plasma desktop did not become ready"));
    }
    emit("LIVE_READY", "plasmashell-active");
    smoke_check("LIVE")?;
    let target = Path::new(TARGET_BY_ID).canonicalize().map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "dedicated acceptance disk not found",
        )
    })?;
    if !is_block_device(&target) {
        return Err(io::Error::other(
            "acceptance disk symlink did not resolve to a block device",
        ));
    }
    // The daemon takes its source from KYTH_SOURCE_IMAGE in its own
    // EnvironmentFile and falls back to a floating tag when the pin is
    // absent; resolve the pin here and fail closed exactly like the raw
    // path does before it passes the pin to bootc.
    let source_ref = installer_source_ref()?;
    if !valid_update_ref(&source_ref) {
        return Err(io::Error::other(
            "installer source image reference contains unsupported characters",
        ));
    }
    let target_ref = installer_target_ref();
    let session = prepare_installer_daemon()?;
    let (status, body) = daemon_request("GET", "/api/disks", &session.token, None)?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "installer disk inventory answered HTTP {status}: {}",
            daemon_error_message(&body)
        )));
    }
    let inventory: Value = serde_json::from_str(&body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let disk = acceptance_disk_from_inventory(&inventory, &target).ok_or_else(|| {
        io::Error::other(format!(
            "dedicated acceptance disk {} is missing from the installer inventory or hosts the live system",
            target.display()
        ))
    })?;
    // Windows variant: the install is an NTFS shrink of the prepared
    // Windows partition, chosen by the daemon's own candidacy flag.
    // Record the volume identity first so the post-install probe (and
    // the installed lifecycle) can prove the shrink preserved it.
    let mut windows_target: Option<(String, String)> = None;
    let request = if windows_mode() {
        let (status, body) = daemon_request(
            "GET",
            &format!("/api/partitions?disk={}", percent_encode(&disk)),
            &session.token,
            None,
        )?;
        if status != 200 {
            return Err(io::Error::other(format!(
                "installer partition inventory answered HTTP {status}: {}",
                daemon_error_message(&body)
            )));
        }
        let partitions: Value = serde_json::from_str(&body)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let (partition, resize_gib) = windows_resize_target_from_partitions(&partitions)
            .ok_or_else(|| {
                io::Error::other(
                    "installer inventory offers no NTFS shrink candidate on the \
                     acceptance disk; the prepared Windows partition is missing \
                     or below the 96 GiB candidacy minimum",
                )
            })?;
        let uuid = ntfs_uuids(Some(&target.display().to_string()))
            .into_iter()
            .find(|(name, _)| name == &partition)
            .map(|(_, uuid)| uuid)
            .filter(|uuid| !uuid.is_empty())
            .ok_or_else(|| {
                io::Error::other(format!(
                    "prepared NTFS partition {partition} has no readable volume UUID"
                ))
            })?;
        emit(
            "WINDOWS_NTFS_BEFORE",
            format!("device={partition} uuid={uuid}"),
        );
        windows_target = Some((partition.clone(), uuid));
        daemon_windows_start_request(
            &disk,
            ACCEPTANCE_HOSTNAME,
            ACCEPTANCE_USERNAME,
            ACCEPTANCE_PASSWORD,
            &partition,
            resize_gib,
        )
    } else {
        daemon_start_request(
            &disk,
            ACCEPTANCE_HOSTNAME,
            ACCEPTANCE_USERNAME,
            ACCEPTANCE_PASSWORD,
        )
    };
    emit("INSTALL_STARTED", target.display().to_string());
    let (status, body) = daemon_request(
        "POST",
        "/api/start",
        &session.token,
        Some(&request.to_string()),
    )?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "installer start answered HTTP {status}: {}",
            daemon_error_message(&body)
        )));
    }
    daemon_stream_terminal_state(&session.token)?;
    let (status, body) = daemon_request("GET", "/api/report", &session.token, None)?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "installer report answered HTTP {status}: {}",
            daemon_error_message(&body)
        )));
    }
    let report: Value = serde_json::from_str(&body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let failures = report_failures(&report);
    if !failures.is_empty() {
        return Err(io::Error::other(format!(
            "installer assurance failed: {}",
            failures.join(", ")
        )));
    }
    if let Some((partition, uuid_before)) = &windows_target {
        let uuid_after = ntfs_uuids(Some(&target.display().to_string()))
            .into_iter()
            .find(|(name, _)| name == partition)
            .map(|(_, uuid)| uuid)
            .unwrap_or_default();
        if uuid_after.is_empty() {
            return Err(io::Error::other(format!(
                "NTFS partition {partition} is missing or lost its volume \
                 identity during the alongside install"
            )));
        }
        if !uuid_after.eq_ignore_ascii_case(uuid_before) {
            return Err(io::Error::other(format!(
                "NTFS volume identity changed during the alongside install: \
                 {uuid_before} -> {uuid_after}"
            )));
        }
        emit(
            "WINDOWS_NTFS_AFTER",
            format!("device={partition} uuid={uuid_after}"),
        );
    }
    emit("INSTALL_COMPLETE", target_ref);
    power("reboot");
    Ok(())
}

fn state_value() -> String {
    acceptance_state_from_text(Some(&read_trimmed(STATE_FILE))).to_owned()
}

fn initial_digest() -> io::Result<String> {
    let value = read_trimmed(INITIAL_DIGEST_FILE);
    if value.is_empty() {
        Err(io::Error::other("initial deployment digest is missing"))
    } else {
        Ok(value)
    }
}

fn write_state(value: &str) -> io::Result<()> {
    atomic_write_text(STATE_FILE, &format!("{value}\n"), Some(0o600))
}

fn active_graphical_session() -> Option<(String, Vec<(String, String)>)> {
    let seat = run_bounded(
        &[
            "loginctl".into(),
            "show-seat".into(),
            "seat0".into(),
            "-p".into(),
            "ActiveSession".into(),
            "--value".into(),
        ],
        Duration::from_secs(5),
    )
    .ok()?;
    let session = String::from_utf8_lossy(&seat.stdout).trim().to_owned();
    if session.is_empty() {
        return None;
    }
    let owner = run_bounded(
        &[
            "loginctl".into(),
            "show-session".into(),
            session,
            "-p".into(),
            "Name".into(),
            "--value".into(),
        ],
        Duration::from_secs(5),
    )
    .ok()?;
    let username = String::from_utf8_lossy(&owner.stdout).trim().to_owned();
    if username.is_empty() {
        return None;
    }
    let uid = run_bounded(
        &["id".into(), "-u".into(), username.clone()],
        Duration::from_secs(5),
    )
    .ok()?;
    let uid = String::from_utf8_lossy(&uid.stdout)
        .trim()
        .parse::<u32>()
        .ok()?;
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let wayland = fs::read_dir(&runtime).ok()?.flatten().find_map(|entry| {
        let name = entry.file_name().to_string_lossy().into_owned();
        name.starts_with("wayland-").then_some(name)
    });
    let x11 = fs::read_dir("/tmp/.X11-unix")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .find_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with('X').then_some(name)
        });
    if wayland.is_none() && x11.is_none() {
        return None;
    }
    let home = fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.first() == Some(&username.as_str()) && fields.len() > 5)
                .then_some(fields[5].to_owned())
        })?;
    let mut environment = vec![
        ("HOME".into(), home.clone()),
        ("LOGNAME".into(), username.clone()),
        ("USER".into(), username.clone()),
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("XDG_RUNTIME_DIR".into(), runtime.display().to_string()),
        ("XDG_CURRENT_DESKTOP".into(), "KDE".into()),
        (
            "DBUS_SESSION_BUS_ADDRESS".into(),
            format!("unix:path={}/bus", runtime.display()),
        ),
    ];
    if let Some(value) = wayland {
        environment.push(("WAYLAND_DISPLAY".into(), value));
    }
    if let Some(value) = x11 {
        environment.push((
            "DISPLAY".into(),
            format!(":{}", value.trim_start_matches('X')),
        ));
    }
    let xauthority = Path::new(&home).join(".Xauthority");
    if xauthority.is_file() {
        environment.push(("XAUTHORITY".into(), xauthority.display().to_string()));
    }
    Some((username, environment))
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                vec![byte as char]
            } else {
                format!("%{byte:02X}").chars().collect()
            }
        })
        .collect()
}

fn hub_pages() -> io::Result<Vec<(String, String)>> {
    let manifest: Value = serde_json::from_str(&fs::read_to_string(HUB_ROUTE_MANIFEST)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let destinations = manifest
        .get("destinations")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("Hub route manifest has no destinations"))?;
    let mut pages = vec![("Welcome".to_owned(), "/".to_owned())];
    for destination in destinations {
        let key = destination
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("Hub destination has no key"))?;
        let route = destination
            .get("route")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("Hub destination has no route"))?;
        pages.push((key.to_owned(), route.to_owned()));
        if let Some(sections) = destination.get("sections").and_then(Value::as_array) {
            for section in sections {
                let section_key = section
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| io::Error::other("Hub section has no key"))?;
                pages.push((
                    section_key.to_owned(),
                    format!("{route}?section={}", percent_encode(section_key)),
                ));
            }
        }
    }
    let mut keys = std::collections::HashSet::new();
    if pages.iter().any(|(key, _)| !keys.insert(key)) {
        return Err(io::Error::other(
            "Hub route manifest contains duplicate page keys",
        ));
    }
    Ok(pages)
}

fn hub_start(
    username: &str,
    environment: &[(String, String)],
    page: &str,
    evidence: &Path,
    degraded: bool,
) -> io::Result<Child> {
    let output = File::create(evidence.with_extension("process.log"))?;
    let mut command = Command::new("runuser");
    command.args(["-u", username, "--", "env"]);
    command.arg(format!("KYTH_HUB_ACCEPTANCE_FILE={}", evidence.display()));
    if degraded {
        command.arg("KYTH_HUB_ACCEPTANCE_DEGRADED=1");
    }
    for (key, value) in environment {
        if !value.is_empty() {
            command.arg(format!("{key}={value}"));
        }
    }
    command.args([HUB_BINARY, "--page", page]);
    command
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output));
    command.spawn()
}

fn hub_stop(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = child.kill();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(8) {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn hub_event(evidence: &Path, event: &str) -> Option<serde_json::Map<String, Value>> {
    let prefix = format!("KYTH_HUB_ACCEPTANCE:{event}:");
    fs::read_to_string(evidence)
        .ok()?
        .lines()
        .rev()
        .find_map(|line| {
            let payload = line.strip_prefix(&prefix)?;
            match serde_json::from_str::<Value>(payload).ok()? {
                Value::Object(object) => Some(object),
                _ => None,
            }
        })
}

fn wait_hub_event(evidence: &Path, event: &str) -> Option<serde_json::Map<String, Value>> {
    let deadline = Instant::now() + HUB_ACCEPTANCE_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(value) = hub_event(evidence, event) {
            return Some(value);
        }
        thread::sleep(Duration::from_millis(500));
    }
    None
}

fn hub_launch_check(
    username: &str,
    environment: &[(String, String)],
    page: &str,
    route: &str,
    evidence: &Path,
) -> bool {
    let _ = fs::remove_file(evidence);
    let Ok(mut child) = hub_start(username, environment, page, evidence, false) else {
        return false;
    };
    let result = wait_hub_event(evidence, "deep-link").is_some_and(|event| {
        event.get("page").and_then(Value::as_str) == Some(page)
            && event.get("route").and_then(Value::as_str) == Some(route)
            && event.get("source").and_then(Value::as_str) == Some("initial")
    });
    hub_stop(&mut child);
    result
}

fn ensure_graphical_session() -> Option<(String, Vec<(String, String)>)> {
    if let Some(session) = active_graphical_session() {
        return Some(session);
    }
    let username = "kyth-acceptance";
    let account_missing = run_bounded(
        &["id".into(), "-u".into(), username.into()],
        Duration::from_secs(5),
    )
    .map_or(true, |output| !output.status.success());
    if account_missing
        && !run_bounded(
            &[
                "useradd".into(),
                "--create-home".into(),
                "--shell".into(),
                "/bin/bash".into(),
                username.into(),
            ],
            Duration::from_secs(30),
        )
        .is_ok_and(|output| output.status.success())
    {
        return None;
    }
    atomic_write_text(
        "/etc/plasmalogin.conf.d/90-kyth-vm-acceptance.conf",
        "[Autologin]\nUser=kyth-acceptance\nSession=plasma.desktop\nRelogin=true\n",
        Some(0o644),
    )
    .ok()?;
    let restart = run_bounded(
        &[
            "systemctl".into(),
            "restart".into(),
            "display-manager.service".into(),
            "--no-block".into(),
        ],
        Duration::from_secs(30),
    )
    .ok()?;
    if !restart.status.success() {
        return None;
    }
    for _ in 0..60 {
        if let Some(session) = active_graphical_session() {
            return Some(session);
        }
        thread::sleep(Duration::from_secs(1));
    }
    None
}

fn run_hub_acceptance() -> io::Result<()> {
    let (username, environment) = ensure_graphical_session().ok_or_else(|| {
        io::Error::other("active graphical session for installed Hub acceptance was not found")
    })?;
    let evidence = PathBuf::from(format!("/tmp/kyth-hub-acceptance-{}.log", unsafe {
        libc::geteuid()
    }));
    emit("HUB_BINARY_OK", HUB_BINARY);
    let pages = hub_pages()?;
    for (page, route) in &pages {
        if !hub_launch_check(&username, &environment, page, route, &evidence) {
            return Err(io::Error::other(format!(
                "Hub --page deep link failed for {page:?}"
            )));
        }
    }
    emit(
        "HUB_DEEP_LINKS_OK",
        pages
            .iter()
            .map(|(page, route)| format!("{page}={route}"))
            .collect::<Vec<_>>()
            .join("; "),
    );
    let _ = fs::remove_file(&evidence);
    let mut first = hub_start(&username, &environment, "Welcome", &evidence, false)?;
    if wait_hub_event(&evidence, "deep-link").is_none() {
        hub_stop(&mut first);
        return Err(io::Error::other("Hub first launch did not resolve Welcome"));
    }
    let _ = fs::remove_file(&evidence);
    let mut second = hub_start(&username, &environment, "Updates", &evidence, false)?;
    let forwarded = wait_hub_event(&evidence, "deep-link").is_some_and(|event| {
        event.get("page").and_then(Value::as_str) == Some("Updates")
            && event.get("source").and_then(Value::as_str) == Some("single-instance")
    });
    hub_stop(&mut second);
    hub_stop(&mut first);
    if !forwarded {
        return Err(io::Error::other(
            "Hub second launch did not forward the Updates page",
        ));
    }
    emit(
        "HUB_SECOND_LAUNCH_OK",
        "Updates forwarded to the existing Hub process",
    );
    let _ = fs::remove_file(&evidence);
    let mut degraded = hub_start(&username, &environment, "Welcome", &evidence, true)?;
    let dashboard = wait_hub_event(&evidence, "dashboard");
    hub_stop(&mut degraded);
    if dashboard
        .as_ref()
        .and_then(|event| event.get("state"))
        .and_then(Value::as_str)
        != Some("degraded")
        || dashboard
            .as_ref()
            .and_then(|event| event.get("label"))
            .and_then(Value::as_str)
            != Some("Status unavailable")
    {
        return Err(io::Error::other(
            "Hub dashboard did not report its unavailable-data state honestly",
        ));
    }
    emit("HUB_DASHBOARD_DEGRADED_OK", "Status unavailable");
    let _ = fs::remove_file(&evidence);
    let mut updates = hub_start(&username, &environment, "Updates", &evidence, false)?;
    let update_probe = wait_hub_event(&evidence, "updates-probe");
    let privilege_probe = wait_hub_event(&evidence, "privileged-failure");
    hub_stop(&mut updates);
    let update_state = update_probe
        .as_ref()
        .and_then(|event| event.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if !matches!(update_state, "ok" | "degraded")
        || privilege_probe
            .as_ref()
            .and_then(|event| event.get("state"))
            .and_then(Value::as_str)
            != Some("expected")
    {
        return Err(io::Error::other(
            "Hub Updates page did not report its probes honestly",
        ));
    }
    emit("HUB_UPDATES_OK", update_state);
    emit("HUB_PRIVILEGED_FAILURE_OK", "allowlist rejection surfaced");
    Ok(())
}

fn installed_lifecycle() -> io::Result<()> {
    fs::create_dir_all(STATE_DIR)?;
    let reference = update_ref();
    if !valid_update_ref(&reference) {
        return Err(io::Error::other(
            "update image reference contains unsupported characters",
        ));
    }
    if !wait_for_desktop("installed") {
        return Err(io::Error::other(
            "installed display manager did not become ready",
        ));
    }
    match state_value().as_str() {
        "fresh" => {
            emit("INSTALLED_READY", "display-manager-active");
            selinux_enforcing()?;
            first_boot_check()?;
            if secure_boot_mode() {
                secure_boot_check()?;
            }
            if windows_mode() {
                windows_ntfs_survived()?;
            }
            if network_check_enabled() {
                network_check()?;
            }
            smoke_check("INSTALLED")?;
            if !Path::new(HUB_BINARY).is_file() {
                return Err(io::Error::other(
                    "installed Rust/Tauri Hub binary is missing",
                ));
            }
            if !Path::new(HUB_ROUTE_MANIFEST).is_file() {
                return Err(io::Error::other("Hub route manifest is missing"));
            }
            run_hub_acceptance()?;
            let initial = booted_digest();
            if initial.is_empty() {
                return Err(io::Error::other("could not read initial booted digest"));
            }
            atomic_write_text(INITIAL_DIGEST_FILE, &format!("{initial}\n"), Some(0o600))?;
            if reference.is_empty() {
                emit("COMPLETE", "install-only");
                power("poweroff");
            } else {
                write_state("update-staged")?;
                emit("UPDATE_STARTED", &reference);
                run_logged(
                    &["bootc".into(), "switch".into(), reference.clone()],
                    COMMAND_TIMEOUT,
                    "bootc switch failed",
                )?;
                emit("UPDATE_STAGED", &reference);
                power("reboot");
            }
        }
        "update-staged" => {
            let initial = initial_digest()?;
            let current = booted_digest();
            if current.is_empty() || current == initial {
                return Err(io::Error::other(
                    "updated deployment did not boot a different digest",
                ));
            }
            if deployment_count() < 2 {
                return Err(io::Error::other(
                    "updated system does not expose a rollback deployment",
                ));
            }
            emit("UPDATE_BOOTED", &current);
            smoke_check("UPDATE")?;
            write_state("rollback-staged")?;
            run_logged(
                &["bootc".into(), "rollback".into()],
                COMMAND_TIMEOUT,
                "bootc rollback failed",
            )?;
            emit("ROLLBACK_STAGED", initial);
            power("reboot");
        }
        "rollback-staged" => {
            let initial = initial_digest()?;
            let current = booted_digest();
            if current.is_empty() || current != initial {
                return Err(io::Error::other(
                    "rollback did not restore the initial deployment digest",
                ));
            }
            emit("ROLLBACK_BOOTED", &current);
            smoke_check("ROLLBACK")?;
            emit("COMPLETE", "update-and-rollback");
            let _ = fs::remove_file(STATE_FILE);
            power("poweroff");
        }
        state => {
            return Err(io::Error::other(format!(
                "unknown acceptance state: {state}"
            )))
        }
    }
    Ok(())
}

pub fn run() -> io::Result<ExitCode> {
    if !enabled() {
        return Ok(ExitCode::SUCCESS);
    }
    let result = if Path::new(INSTALLER_ENV_FILE).is_file() {
        if installer_daemon_mode() {
            install_via_installer_daemon()
        } else {
            install_from_live_iso()
        }
    } else {
        installed_lifecycle()
    };
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => {
            emit("FAILED", error.to_string());
            power("poweroff");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_restricted_update_refs() {
        assert!(valid_update_ref(""));
        assert!(valid_update_ref(
            "ghcr.io/mrtrickdotorg/kyth:testing@sha256:abc"
        ));
        assert!(!valid_update_ref("ghcr.io/kyth;poweroff"));
        assert!(!valid_update_ref("image with spaces"));
        assert!(!valid_update_ref(&"a".repeat(UPDATE_REF_MAX + 1)));
    }

    #[test]
    fn decodes_bootc_and_ostree_shapes() {
        assert_eq!(
            booted_digest_from_json(
                "{\"status\":{\"booted\":{\"image\":{\"imageDigest\":\"sha256:abc\"}}}}"
            ),
            Some("sha256:abc".into())
        );
        assert_eq!(booted_digest_from_json("{\"status\":{\"booted\":{\"image\":{\"image\":{\"imageDigest\":\"sha256:nested\"}}}}}"), Some("sha256:nested".into()));
        assert_eq!(deployment_count_from_json("[{\"id\":1},{\"id\":2}]"), 2);
        assert_eq!(
            deployment_count_from_json("{\"deployments\":[{\"id\":1}] }"),
            1
        );
    }

    #[test]
    fn parses_pinned_installer_source_from_env() {
        assert_eq!(
            source_ref_from_env(
                "KYTH_TARGET_IMAGE=x\nKYTH_SOURCE_IMAGE=ghcr.io/mrtrickdotorg/kyth@sha256:abc\n"
            ),
            Some("ghcr.io/mrtrickdotorg/kyth@sha256:abc".into())
        );
        assert_eq!(source_ref_from_env("KYTH_TARGET_IMAGE=x\n"), None);
        assert_eq!(source_ref_from_env(""), None);
        assert_eq!(
            source_ref_from_env("KYTH_SOURCE_IMAGE='ghcr.io/mrtrickdotorg/kyth:testing'\n"),
            Some("ghcr.io/mrtrickdotorg/kyth:testing".into())
        );
        assert_eq!(source_ref_from_env("KYTH_SOURCE_IMAGE=\n"), None);
    }

    #[test]
    fn parses_failed_units_from_systemctl_output() {
        assert!(failed_units_from_output("").is_empty());
        assert!(failed_units_from_output("\n").is_empty());
        assert_eq!(
            failed_units_from_output(
                "● foo.service loaded failed failed Foo Service\n\
                 bar.service loaded failed failed Bar Service\n"
            ),
            vec!["foo.service".to_string(), "bar.service".to_string()]
        );
    }

    #[test]
    fn derives_registry_host_from_reference() {
        assert_eq!(
            registry_host("ghcr.io/mrtrickdotorg/kyth:testing"),
            "ghcr.io"
        );
        assert_eq!(registry_host("ghcr.io"), "ghcr.io");
    }

    fn complete_report() -> Value {
        let checks: Vec<Value> = ASSURANCE_CHECK_NAMES
            .iter()
            .map(|name| serde_json::json!({"name": name, "status": "pass", "detail": ""}))
            .collect();
        serde_json::json!({"status": "complete", "checks": checks})
    }

    #[test]
    fn daemon_start_request_matches_the_native_contract() {
        let request = daemon_start_request(
            "/dev/vda",
            "kyth-acceptance",
            "kyth-acceptance",
            "kyth-acceptance",
        );
        let object = request.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "acknowledged_irreversible",
                "confirm_backup",
                "confirm_current",
                "confirm_erase",
                "disk",
                "encryption",
                "flatpaks",
                "free_region_end",
                "free_region_start",
                "hostname",
                "install_mode",
                "kernel",
                "keymap",
                "locale",
                "mok_password",
                "password",
                "resize_gib",
                "resize_partition",
                "target_partition",
                "timezone",
                "tpm_recovery_ack",
                "username",
            ]
        );
        assert_eq!(request["disk"], "/dev/vda");
        assert_eq!(request["install_mode"], "wipe");
        assert_eq!(request["confirm_backup"], true);
        assert_eq!(request["confirm_erase"], true);
        assert_eq!(request["acknowledged_irreversible"], true);
        assert_eq!(request["encryption"], "none");
        assert_eq!(request["hostname"], "kyth-acceptance");
        assert_eq!(request["username"], "kyth-acceptance");
        assert_eq!(request["password"], "kyth-acceptance");
    }

    #[test]
    fn selects_only_the_dedicated_acceptance_disk() {
        let inventory = serde_json::json!([
            {"name": "/dev/sda", "current": true},
            {"name": "/dev/vda", "current": false},
        ]);
        assert_eq!(
            acceptance_disk_from_inventory(&inventory, Path::new("/dev/vda")),
            Some("/dev/vda".to_string())
        );
        // The disk hosting the live system is never eligible.
        assert_eq!(
            acceptance_disk_from_inventory(&inventory, Path::new("/dev/sda")),
            None
        );
        assert_eq!(
            acceptance_disk_from_inventory(&inventory, Path::new("/dev/vdb")),
            None
        );
        assert_eq!(
            acceptance_disk_from_inventory(&serde_json::json!({}), Path::new("/dev/vda")),
            None
        );
    }

    #[test]
    fn report_evaluation_requires_completion_and_passing_assurance() {
        assert!(report_failures(&complete_report()).is_empty());

        // A warning progress check (the daemon records these on
        // successful installs, e.g. boot_entries) does not fail the run.
        let mut report = complete_report();
        report["checks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"name": "boot_entries", "status": "warning"}));
        assert!(report_failures(&report).is_empty());

        // A missing assurance check fails, naming the check.
        let mut report = complete_report();
        report["checks"]
            .as_array_mut()
            .unwrap()
            .retain(|check| check["name"] != "selinux");
        assert_eq!(
            report_failures(&report),
            ["assurance check selinux is missing"]
        );

        // A non-pass assurance check fails, naming the check.
        let mut report = complete_report();
        for check in report["checks"].as_array_mut().unwrap() {
            if check["name"] == "selinux" {
                check["status"] = Value::String("fail".into());
            }
        }
        assert_eq!(
            report_failures(&report),
            ["assurance check selinux did not pass"]
        );

        // Any other check with an explicit fail status fails the run.
        let mut report = complete_report();
        report["checks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"name": "power", "status": "fail"}));
        assert_eq!(report_failures(&report), ["installer check power failed"]);

        // A job that did not complete fails even with passing checks.
        let mut report = complete_report();
        report["status"] = Value::String("failed".into());
        assert_eq!(
            report_failures(&report),
            ["installer job status is \"failed\""]
        );

        // No checks at all cannot be verified as passing.
        let report = serde_json::json!({"status": "complete", "checks": []});
        assert_eq!(
            report_failures(&report),
            ["installer report carries no checks"]
        );
    }

    #[test]
    fn parses_daemon_http_heads_and_error_messages() {
        let mut cursor =
            io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec());
        let (status, length) = read_http_head(&mut cursor).unwrap();
        assert_eq!(status, 200);
        assert_eq!(length, Some(2));

        let mut cursor = io::Cursor::new(
            b"HTTP/1.1 409 Conflict\r\nContent-Type: text/event-stream\r\n\r\n".to_vec(),
        );
        let (status, length) = read_http_head(&mut cursor).unwrap();
        assert_eq!(status, 409);
        assert_eq!(length, None);

        assert_eq!(
            daemon_error_message("{\"started\":false,\"message\":\"disk busy\"}"),
            "disk busy"
        );
        assert_eq!(daemon_error_message("{\"error\":\"nope\"}"), "nope");
        assert_eq!(daemon_error_message("plain failure"), "plain failure");
    }

    #[test]
    fn windows_start_request_is_a_resize_of_the_prepared_partition() {
        let request = daemon_windows_start_request(
            "/dev/vda",
            "kyth-acceptance",
            "kyth-acceptance",
            "kyth-acceptance",
            "/dev/vda2",
            63,
        );
        // Same field set as the wipe request; only the mode fields move.
        let wipe = daemon_start_request(
            "/dev/vda",
            "kyth-acceptance",
            "kyth-acceptance",
            "kyth-acceptance",
        );
        let mut keys: Vec<&str> = request
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut wipe_keys: Vec<&str> = wipe
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        wipe_keys.sort_unstable();
        assert_eq!(keys, wipe_keys);
        assert_eq!(request["install_mode"], "resize_ntfs");
        assert_eq!(request["resize_partition"], "/dev/vda2");
        assert_eq!(request["resize_gib"], 63);
        assert_eq!(request["confirm_erase"], true);
        assert_eq!(request["encryption"], "none");
    }

    #[test]
    fn windows_resize_sizing_keeps_the_windows_floor() {
        let gib = 1024 * 1024 * 1024;
        // Below the installer's 96 GiB candidacy minimum: no target.
        assert_eq!(windows_resize_gib(64 * gib), None);
        assert_eq!(windows_resize_gib(96 * gib - 1), None);
        // At the minimum KythOS gets exactly its 32 GiB floor.
        assert_eq!(windows_resize_gib(96 * gib), Some(32));
        // The 128 GiB windows-variant disk: ~127 GiB NTFS -> 63 GiB.
        assert_eq!(windows_resize_gib(127 * gib), Some(63));
    }

    #[test]
    fn windows_target_requires_the_daemons_own_candidate_flag() {
        let partitions = serde_json::json!([
            {"name": "/dev/vda1", "size_bytes": 512 * 1024 * 1024,
             "fstype": "vfat", "ntfs_resize_candidate": false},
            {"name": "/dev/vda2", "size_bytes": 127_u64 * 1024 * 1024 * 1024,
             "fstype": "ntfs", "ntfs_resize_candidate": true},
        ]);
        assert_eq!(
            windows_resize_target_from_partitions(&partitions),
            Some(("/dev/vda2".to_string(), 63))
        );
        // An NTFS partition the daemon does not flag (e.g. too small) is
        // never selected behind its back.
        let small = serde_json::json!([
            {"name": "/dev/vda2", "size_bytes": 63_u64 * 1024 * 1024 * 1024,
             "fstype": "ntfs", "ntfs_resize_candidate": false},
        ]);
        assert_eq!(windows_resize_target_from_partitions(&small), None);
        assert_eq!(
            windows_resize_target_from_partitions(&serde_json::json!({})),
            None
        );
    }

    #[test]
    fn parses_ntfs_rows_from_lsblk_output() {
        let output = "/dev/vda\n\
                      /dev/vda1 vfat 8CA4-F0D2\n\
                      /dev/vda2 ntfs 5A8C4E2F12345678\n\
                      /dev/vda3 btrfs 9f1c-UUID\n\
                      /dev/vdb1 ntfs3 FEDCBA0987654321\n\
                      /dev/vdb2 ntfs\n";
        assert_eq!(
            ntfs_entries_from_lsblk(output),
            [
                ("/dev/vda2".to_string(), "5A8C4E2F12345678".to_string()),
                ("/dev/vdb1".to_string(), "FEDCBA0987654321".to_string()),
                ("/dev/vdb2".to_string(), String::new()),
            ]
        );
        assert!(ntfs_entries_from_lsblk("").is_empty());
    }

    #[test]
    fn parses_mokutil_secure_boot_state() {
        assert_eq!(
            secure_boot_state_from_output("SecureBoot enabled\n"),
            Some(true)
        );
        assert_eq!(
            secure_boot_state_from_output("SecureBoot disabled\n"),
            Some(false)
        );
        assert_eq!(secure_boot_state_from_output(""), None);
        assert_eq!(
            secure_boot_state_from_output("mokutil: EFI variables are not supported\n"),
            None
        );
    }

    #[test]
    fn normalizes_state_and_events() {
        assert_eq!(acceptance_state_from_text(None), "fresh");
        assert_eq!(acceptance_state_from_text(Some("bad")), "unknown");
        assert_eq!(
            acceptance_event("FAILED", "line one\nline two"),
            "KYTH_ACCEPTANCE:FAILED:line one line two"
        );
    }
}
