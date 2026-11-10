//! LUKS device discovery and one-time recovery-key enrollment for
//! TPM2-bound installs.
//!
//! The daemon runs these helpers in-process: it is already root and runs
//! `/usr/sbin/cryptsetup` for assurance. Nothing here may stream command
//! output — `systemd-cryptenroll --recovery-key` prints the generated key
//! to stdout, and the streaming helpers feed stdout into the persisted
//! installer log. Output is captured, parsed in memory, and the key is
//! returned in a `Zeroizing` wrapper; raw stdout never reaches a log, an
//! error message, or a persisted record.

use std::io::Write;
use std::process::{Command, Stdio};

use serde::Deserialize;
use zeroize::Zeroizing;

const CRYPTENROLL: &str = "/usr/bin/systemd-cryptenroll";
const CRYPTSETUP: &str = "/usr/sbin/cryptsetup";
const LSBLK: &str = "/usr/sbin/lsblk";
const RECOVERY_KEY_MARKER: &str = "A secret recovery key has been generated for this volume:";
/// The only device-mapper name the installer provisions. The storage
/// layer, the boot kargs (`root=/dev/mapper/cryptroot`), and the
/// installed crypttab all key off this single name.
pub(crate) const CRYPTROOT_NAME: &str = "cryptroot";
/// cryptsetup operations on a healthy disk finish in seconds (Argon2
/// calibration dominates); the bound only exists so a wedged device
/// cannot hang the exec helper forever.
const CRYPTSETUP_TIMEOUT_SECONDS: u64 = 600;

/// Parse `lsblk -npro NAME,FSTYPE` output into the names of the
/// `crypto_LUKS` partitions it lists, in listing order.
pub(crate) fn luks_devices(lsblk_output: &str) -> Vec<String> {
    let mut devices = Vec::new();
    for line in lsblk_output.lines() {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(name), Some(fstype)) if fstype.eq_ignore_ascii_case("crypto_LUKS") => {
                devices.push(name.to_string());
            }
            _ => {}
        }
    }
    devices
}

/// Discover the crypto_LUKS partitions on `disk` via lsblk, captured (never
/// streamed) like every other command in this module.
pub(crate) fn discover_luks_devices(disk: &str) -> Result<Vec<String>, String> {
    let output = Command::new(LSBLK)
        .args(["-npro", "NAME,FSTYPE", disk])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not run {LSBLK}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{LSBLK} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(luks_devices(&String::from_utf8_lossy(&output.stdout)))
}

/// The exact argv that enrolls a recovery key on a TPM2-bound LUKS volume:
/// the TPM2 token is the only existing credential, so it authorizes the
/// enrollment non-interactively.
pub(crate) fn enroll_recovery_argv(device: &str) -> Vec<String> {
    vec![
        CRYPTENROLL.to_string(),
        "--unlock-tpm2-device=auto".to_string(),
        "--recovery-key".to_string(),
        device.to_string(),
    ]
}

/// A systemd recovery key is eight dash-separated groups drawn from
/// `[a-z2-7]` (lowercase base32 without the ambiguous digits).
fn is_recovery_key_shape(token: &str) -> bool {
    let groups: Vec<&str> = token.split('-').collect();
    groups.len() == 8
        && groups.iter().all(|group| {
            !group.is_empty()
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
        })
}

/// Extract the generated recovery key from `systemd-cryptenroll` stdout.
/// The key is the first key-shaped token on a line *after* the marker
/// line; key-shaped text anywhere else (or without the marker) is not a
/// key this command generated and is rejected.
pub(crate) fn parse_recovery_key(stdout: &str) -> Option<String> {
    let mut after_marker = false;
    for line in stdout.lines() {
        if after_marker {
            for token in line.split_whitespace() {
                if is_recovery_key_shape(token) {
                    return Some(token.to_string());
                }
            }
        }
        if line.contains(RECOVERY_KEY_MARKER) {
            after_marker = true;
        }
    }
    None
}

/// Generate a recovery key for `device` and return it in memory only.
///
/// stdout/stderr are captured with `Command::output`; on failure the
/// error carries cryptenroll's stderr diagnostic with any generated key
/// scrubbed out first — the raw stdout is never included anywhere.
pub(crate) fn generate_recovery_key(device: &str) -> Result<Zeroizing<String>, String> {
    let argv = enroll_recovery_argv(device);
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            format!("could not run {CRYPTENROLL} to generate a recovery key: {error}")
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        // Parse first: if a key was generated before the failure, it must
        // not leak back out through the stderr diagnostic.
        let mut detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if let Some(key) = parse_recovery_key(&stdout) {
            detail = detail.replace(&key, "[redacted]");
        }
        if detail.is_empty() {
            detail = format!("exit status {}", output.status);
        }
        return Err(format!(
            "systemd-cryptenroll failed to generate a recovery key: {detail}"
        ));
    }
    parse_recovery_key(&stdout)
        .map(Zeroizing::new)
        .ok_or_else(|| "systemd-cryptenroll did not report a generated recovery key".to_string())
}

/// Generate the one-time recovery key for the (single) LUKS volume a
/// `tpm2` install left on `target_disk`. Discovery mirrors the assurance
/// check: when several LUKS partitions exist, the first one — the same
/// one assurance finds first — is enrolled.
pub(crate) fn generate_tpm_recovery_key(target_disk: &str) -> Result<Zeroizing<String>, String> {
    let disk = crate::installer_plan::normalize_device_path(target_disk)
        .ok_or_else(|| "recovery key enrollment needs a valid installed target disk".to_string())?;
    let devices = discover_luks_devices(&disk)?;
    let device = devices.first().ok_or_else(|| {
        format!("TPM2 encryption was requested but no LUKS partition was found on {disk}")
    })?;
    generate_recovery_key(device)
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// Typed input for the exec helper's `luks-provision` operation: format a
/// partition as LUKS2 and open it, in one helper invocation, so the
/// passphrase crosses the daemon→helper stdin boundary exactly once and
/// exists in exactly two processes.
///
/// Deliberately no `Debug`: the passphrase must never be formattable into
/// a log line, event, or diagnostic — the same posture as
/// `InstallerExecutionInput`. The passphrase travels only in this JSON
/// body and in cryptsetup's stdin (`--key-file=-`); it is never an argv
/// element, never part of a plan, and never written to disk.
#[derive(Deserialize)]
pub(crate) struct LuksProvisionInput {
    /// The partition to format (e.g. `/dev/sda2`). Must be a plain
    /// partition path — an existing mapper device is refused.
    pub device: String,
    /// Mapper name to open the volume under. Allowlisted to
    /// [`CRYPTROOT_NAME`]; the boot kargs and crypttab name it literally.
    pub name: String,
    #[serde(deserialize_with = "deserialize_zeroizing")]
    pub passphrase: Zeroizing<String>,
}

/// The exact argv that formats `device` as LUKS2, reading the passphrase
/// from stdin as the key file. `--batch-mode` suppresses the interactive
/// "Are you sure?" confirmation; the daemon's own confirmations already
/// gated this destructive step.
pub(crate) fn luks_format_argv(device: &str) -> Vec<String> {
    vec![
        CRYPTSETUP.to_string(),
        "luksFormat".to_string(),
        "--type".to_string(),
        "luks2".to_string(),
        "--batch-mode".to_string(),
        "--key-file=-".to_string(),
        device.to_string(),
    ]
}

/// The exact argv that opens the freshly formatted volume under `name`,
/// again reading the passphrase from stdin.
pub(crate) fn luks_open_argv(device: &str, name: &str) -> Vec<String> {
    vec![
        CRYPTSETUP.to_string(),
        "open".to_string(),
        "--type".to_string(),
        "luks2".to_string(),
        "--key-file=-".to_string(),
        device.to_string(),
        name.to_string(),
    ]
}

/// Validate the provision input before any process is spawned: a plain
/// partition device (never an existing mapper node), the allowlisted
/// mapper name, and a non-empty, bounded passphrase. Returns the
/// normalized `(device, name)` pair the argv builders consume.
pub(crate) fn validate_provision_input(
    input: &LuksProvisionInput,
) -> Result<(String, String), String> {
    if input.device.trim().starts_with("/dev/mapper/") {
        return Err("LUKS provision target must be a partition, not a mapper device.".to_string());
    }
    let device = crate::installer_plan::normalize_device_path(&input.device)
        .ok_or_else(|| "LUKS provision device must be a safe partition path.".to_string())?;
    if input.name != CRYPTROOT_NAME {
        return Err(format!(
            "unsupported LUKS mapper name: only {CRYPTROOT_NAME} is provisioned."
        ));
    }
    if input.passphrase.is_empty() {
        return Err("LUKS provision requires a non-empty passphrase.".to_string());
    }
    if input.passphrase.len() > 4096 {
        return Err("LUKS passphrase is too long.".to_string());
    }
    Ok((device, input.name.clone()))
}

/// Replace any occurrence of the passphrase in a diagnostic string. The
/// cryptsetup invocations below never echo stdin, so this is defense in
/// depth: even a future cryptsetup diagnostic that quoted its key file
/// could not carry the secret into the phase error or the helper's
/// stderr.
fn scrub_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "[redacted]")
    }
}

/// Run one cryptsetup step with the passphrase on its stdin. Output is
/// captured, never streamed (this module's standing rule); failures
/// return the stderr diagnostic with any passphrase occurrence scrubbed.
fn run_cryptsetup_with_passphrase(
    argv: &[String],
    passphrase: &Zeroizing<String>,
    step: &str,
) -> Result<(), String> {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not run {CRYPTSETUP} for {step}: {error}"))?;
    // The key file is a few KiB at most and cryptsetup reads stdin before
    // producing output, so writing on this thread cannot deadlock against
    // a full stdout pipe.
    if let Some(mut stdin) = child.stdin.take() {
        let written = stdin.write_all(passphrase.as_bytes());
        drop(stdin);
        if let Err(error) = written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "could not provide the LUKS passphrase for {step}: {error}"
            ));
        }
    }
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= std::time::Duration::from_secs(CRYPTSETUP_TIMEOUT_SECONDS) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "cryptsetup {step} timed out after {CRYPTSETUP_TIMEOUT_SECONDS} seconds"
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not poll cryptsetup {step}: {error}"));
            }
        }
    };
    if status.success() {
        return Ok(());
    }
    // The child has exited; drain whatever it left on stderr. The pipes
    // were not consumed while polling, but cryptsetup's diagnostics are
    // a few lines at most — far below the pipe capacity that could have
    // blocked it.
    let mut detail = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        use std::io::Read;
        let _ = stderr.read_to_string(&mut detail);
    }
    let detail = scrub_secret(detail.trim(), passphrase.as_str());
    let detail = if detail.is_empty() {
        format!("exit status {status}")
    } else {
        detail
    };
    Err(format!("cryptsetup {step} failed: {detail}"))
}

/// Format `input.device` as LUKS2 and open it as `cryptroot`, the whole
/// provisioning step behind the exec helper's `luks-provision` operation.
/// Both cryptsetup invocations read the passphrase from stdin; it never
/// appears in argv (where `/proc/<pid>/cmdline` would expose it to every
/// local process) and never in this function's errors.
pub(crate) fn provision_luks(input: LuksProvisionInput) -> Result<(), String> {
    let (device, name) = validate_provision_input(&input)?;
    run_cryptsetup_with_passphrase(&luks_format_argv(&device), &input.passphrase, "luksFormat")?;
    run_cryptsetup_with_passphrase(&luks_open_argv(&device, &name), &input.passphrase, "open")?;
    let mapper = format!("/dev/mapper/{name}");
    if !std::path::Path::new(&mapper).exists() {
        return Err(format!(
            "cryptsetup reported success but {mapper} does not exist; refusing to continue"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY: &str =
        "abc2def3-ghi4jkl5-mno6pqr7-stu2vwx3-yzab4cde-5fgh6ijk-7lmn2opq-3rst4uvw";

    #[test]
    fn luks_devices_parses_lsblk_listing() {
        let listing = "\
/dev/sda1 vfat
/dev/sda2 crypto_LUKS
/dev/sda3 btrfs
/dev/sda4 CRYPTO_LUKS
/dev/sda5
";
        assert_eq!(luks_devices(listing), ["/dev/sda2", "/dev/sda4"]);
        assert!(luks_devices("").is_empty());
        assert!(luks_devices("/dev/sda1 vfat\n").is_empty());
    }

    #[test]
    fn enroll_argv_unlocks_with_the_tpm2_token() {
        assert_eq!(
            enroll_recovery_argv("/dev/sda2"),
            [
                "/usr/bin/systemd-cryptenroll",
                "--unlock-tpm2-device=auto",
                "--recovery-key",
                "/dev/sda2",
            ]
        );
    }

    #[test]
    fn parse_recovery_key_reads_the_generated_key() {
        let stdout = format!(
            "Enrolling a new recovery key for /dev/sda2.\n\
             A secret recovery key has been generated for this volume:\n\
             {VALID_KEY}\n\
             \n\
             Please store it in a safe place.\n"
        );
        assert_eq!(parse_recovery_key(&stdout).as_deref(), Some(VALID_KEY));
    }

    #[test]
    fn parse_recovery_key_rejects_missing_marker() {
        // A key-shaped token with no marker line is not a generated key.
        let stdout = format!("some earlier output: {VALID_KEY}\n");
        assert_eq!(parse_recovery_key(&stdout), None);
        assert_eq!(parse_recovery_key(""), None);
        assert_eq!(
            parse_recovery_key("A secret recovery key has been generated for this volume:\n"),
            None
        );
    }

    #[test]
    fn parse_recovery_key_rejects_malformed_keys() {
        for candidate in [
            // Seven groups.
            "abc2def3-ghi4jkl5-mno6pqr7-stu2vwx3-yzab4cde-5fgh6ijk-7lmn2opq",
            // Nine groups.
            "abc2def3-ghi4jkl5-mno6pqr7-stu2vwx3-yzab4cde-5fgh6ijk-7lmn2opq-3rst4uvw-xyz2abc3",
            // Uppercase is outside the [a-z2-7] alphabet.
            "ABC2DEF3-GHI4JKL5-MNO6PQR7-STU2VWX3-YZAB4CDE-5FGH6IJK-7LMN2OPQ-3RST4UVW",
            // Digits 0, 1, 8, 9 are outside the alphabet.
            "abc0def1-ghi8jkl9-mno6pqr7-stu2vwx3-yzab4cde-5fgh6ijk-7lmn2opq-3rst4uvw",
            // An empty group.
            "abc2def3--mno6pqr7-stu2vwx3-yzab4cde-5fgh6ijk-7lmn2opq-3rst4uvw",
            // No dashes at all.
            "abc2def3ghi4jkl5mno6pqr7stu2vwx3",
        ] {
            let stdout =
                format!("A secret recovery key has been generated for this volume:\n{candidate}\n");
            assert_eq!(
                parse_recovery_key(&stdout),
                None,
                "candidate must be rejected: {candidate}"
            );
        }
    }

    #[test]
    fn provision_argv_reads_the_passphrase_from_stdin() {
        assert_eq!(
            luks_format_argv("/dev/sda2"),
            [
                "/usr/sbin/cryptsetup",
                "luksFormat",
                "--type",
                "luks2",
                "--batch-mode",
                "--key-file=-",
                "/dev/sda2",
            ]
        );
        assert_eq!(
            luks_open_argv("/dev/sda2", "cryptroot"),
            [
                "/usr/sbin/cryptsetup",
                "open",
                "--type",
                "luks2",
                "--key-file=-",
                "/dev/sda2",
                "cryptroot",
            ]
        );
    }

    #[test]
    fn provision_input_deserializes_and_the_passphrase_never_reaches_argv() {
        let input: LuksProvisionInput = serde_json::from_str(
            r#"{"device":"/dev/sda2","name":"cryptroot","passphrase":"correct horse battery staple"}"#,
        )
        .expect("provision input should deserialize");
        let (device, name) = validate_provision_input(&input).expect("input should validate");
        assert_eq!(device, "/dev/sda2");
        assert_eq!(name, CRYPTROOT_NAME);
        // The passphrase is a stdin payload only: no argv the helper can
        // build from this input may contain it, because argv is world-
        // readable via /proc/<pid>/cmdline while cryptsetup runs.
        for argv in [luks_format_argv(&device), luks_open_argv(&device, &name)] {
            assert!(
                !argv.iter().any(|arg| arg.contains("correct horse")),
                "passphrase leaked into argv: {argv:?}"
            );
        }
    }

    #[test]
    fn provision_input_validation_fails_closed() {
        let build = |device: &str, name: &str, passphrase: &str| {
            serde_json::from_value::<LuksProvisionInput>(serde_json::json!({
                "device": device,
                "name": name,
                "passphrase": passphrase,
            }))
            .expect("fixture input should deserialize")
        };
        // An existing mapper device is not a format target.
        assert!(
            validate_provision_input(&build("/dev/mapper/cryptroot", "cryptroot", "pw"))
                .unwrap_err()
                .contains("mapper device")
        );
        // Only the allowlisted mapper name may be opened.
        assert!(
            validate_provision_input(&build("/dev/sda2", "rootfs", "pw"))
                .unwrap_err()
                .contains("mapper name")
        );
        // No empty passphrases.
        assert!(
            validate_provision_input(&build("/dev/sda2", "cryptroot", ""))
                .unwrap_err()
                .contains("non-empty")
        );
        // Unsafe device shapes never normalize.
        assert!(validate_provision_input(&build("/dev/../etc/passwd", "cryptroot", "pw")).is_err());
        // Validation happens before any spawn: every refusal above is a
        // pure error string, so these are safe to exercise without a
        // device or root.
    }

    #[test]
    fn scrub_secret_removes_every_passphrase_occurrence() {
        assert_eq!(
            scrub_secret(
                "error near correct horse battery staple here",
                "correct horse battery staple"
            ),
            "error near [redacted] here"
        );
        assert_eq!(scrub_secret("nothing to hide", ""), "nothing to hide");
    }

    #[test]
    fn parse_recovery_key_ignores_key_like_text_before_the_marker() {
        let stdout = format!(
            "unrelated earlier line mentions {VALID_KEY} in passing\n\
             A secret recovery key has been generated for this volume:\n\
             {VALID_KEY}\n"
        );
        assert_eq!(parse_recovery_key(&stdout).as_deref(), Some(VALID_KEY));
        // Without anything after the marker, the earlier mention alone
        // does not count.
        let stdout = format!(
            "unrelated earlier line mentions {VALID_KEY} in passing\n\
             A secret recovery key has been generated for this volume:\n"
        );
        assert_eq!(parse_recovery_key(&stdout), None);
    }
}
