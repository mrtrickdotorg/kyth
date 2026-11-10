//! Pure bootc install-command planning.
//!
//! This module deliberately constructs an operation description instead of
//! spawning bootc. The root-owned Rust daemon and its typed helper are the
//! only executors; the unprivileged shell can use this plan for preflight.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BootcInstallInput {
    pub subcommand: String,
    pub source_imgref: String,
    pub target_imgref: String,
    pub target: String,
    /// Reachability preflight runs unless explicitly skipped: an omitted
    /// key must fail fast at validation, not mid-install on the target
    /// disk. `bootc --skip-fetch-check` is an expert opt-out, not the
    /// default.
    #[serde(default)]
    pub skip_fetch_check: bool,
    #[serde(default)]
    pub skip_finalize: bool,
    #[serde(default)]
    pub root_subvolume: bool,
    #[serde(default)]
    pub wipe: bool,
    /// Requested root-device encryption.
    ///
    /// Accepted values are `"none"` (explicit plaintext, the default),
    /// `"tpm2"` (TPM2-bound LUKS via `bootc install to-disk --block-setup
    /// tpm2-luks`), and `"passphrase"` (LUKS2 provisioned by the installer
    /// itself — GPT layout, `cryptsetup luksFormat`, mapper opened as
    /// `cryptroot` — and written with `to-filesystem`, because bootc's
    /// block-setup set has no passphrase mode). `tpm2` is valid only for
    /// `to-disk`; `passphrase` is valid only for `to-filesystem` (the
    /// executor derives that shape from `install_mode == "wipe"` plus this
    /// mode). Any other value, or a mode paired with the wrong
    /// subcommand, fails closed: the installer must never silently fall
    /// back to plaintext when encryption was requested.
    #[serde(default)]
    pub encryption: String,
    /// Extra kernel arguments for `to-filesystem` installs, emitted as
    /// `--karg=<value>` after the root-subvolume karg. Request-time plans
    /// leave this empty: the native executor injects the values at image
    /// time, when the storage phase has provisioned the target and the
    /// LUKS UUID exists (`rd.luks.uuid=…`, `root=/dev/mapper/cryptroot`).
    /// Values are strictly validated in `build_plan` (see `safe_karg`).
    #[serde(default)]
    pub root_kargs: Vec<String>,
    /// TPM recovery acknowledgement for `tpm2` installs. TPM-bound LUKS has
    /// no passphrase, and TPM unlock is bound to this machine: during the
    /// install the daemon enrolls a one-time recovery key on the volume
    /// and shows it to the user exactly once at completion; it is never
    /// stored. If the TPM is reset or the board is replaced, that key is
    /// the only way to unlock the encrypted disk. The installer sets this
    /// only after the user acknowledges that TPM unlock is machine-bound
    /// and that they will record the recovery key when it is shown.
    /// `tpm2` without this acknowledgement fails closed.
    #[serde(default)]
    pub tpm_recovery_ack: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct BootcInstallPlan {
    pub subcommand: String,
    pub argv: Vec<String>,
    pub target: String,
    pub destructive: bool,
    pub requires_network: bool,
    pub executor: &'static str,
}

fn safe_reference(value: &str, label: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 4096 || value.contains("..") {
        return Err(format!("{label} is empty or unsafe."));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'/' | b'_' | b'@' | b':' | b'+' | b'-')
    }) {
        return Err(format!("{label} contains unsupported characters."));
    }
    Ok(value.to_string())
}

fn source_reference(value: &str) -> Result<String, String> {
    let value = safe_reference(value, "source image reference")?;
    let has_transport = [
        "docker://",
        "containers-storage:",
        "oci:",
        "ostree:",
        "dir:",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix));
    if has_transport {
        Ok(value)
    } else {
        Ok(format!("docker://{value}"))
    }
}

/// One kernel argument the executor may inject into a `to-filesystem`
/// plan. Kargs land on the installed system's bootloader entries, so the
/// shape is deliberately narrow: `key=value` tokens over a conservative
/// alphabet (device paths, UUIDs, subvolume names), no whitespace, no
/// shell or bootloader metacharacters.
fn safe_karg(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 {
        return Err("kernel argument is empty or too long.".to_string());
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'=' | b'.' | b'/' | b'_' | b'+' | b':' | b'-')
    }) {
        return Err(format!(
            "kernel argument contains unsupported characters: {value}"
        ));
    }
    Ok(value.to_string())
}

fn safe_absolute_path(value: &str, label: &str) -> Result<String, String> {
    let value = value.trim();
    if !value.starts_with('/') || value.len() > 4096 || value.contains("..") {
        return Err(format!("{label} must be an absolute safe path."));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b':' | b'-')
    }) {
        return Err(format!("{label} contains unsupported characters."));
    }
    Ok(value.to_string())
}

pub(crate) fn build_plan(input: BootcInstallInput) -> Result<BootcInstallPlan, String> {
    let subcommand = input.subcommand.trim().to_ascii_lowercase();
    if !matches!(subcommand.as_str(), "to-disk" | "to-filesystem") {
        return Err(format!(
            "unsupported bootc install subcommand: {subcommand}"
        ));
    }
    let source_imgref = source_reference(&input.source_imgref)?;
    let target_imgref = safe_reference(&input.target_imgref, "target image reference")?;
    let encryption = input.encryption.trim().to_ascii_lowercase();
    if !matches!(encryption.as_str(), "" | "none" | "tpm2" | "passphrase") {
        return Err(format!(
            "encryption unsupported: '{encryption}' is not a supported encryption mode (expected 'none', 'tpm2', or 'passphrase')."
        ));
    }
    if encryption == "tpm2" && !input.tpm_recovery_ack {
        return Err(
            "TPM encryption was requested without acknowledging the recovery risk: TPM unlock is bound to this machine. During the install a one-time recovery key will be generated and shown exactly once; it is never stored, and if the TPM is reset or the board is replaced it is the only way to unlock the disk. Confirm you will record the recovery key before installing."
                .to_string(),
        );
    }
    let target = if subcommand == "to-disk" {
        crate::installer_plan::normalize_device_path(&input.target)
            .ok_or_else(|| "bootc disk target must be a safe device path.".to_string())?
    } else {
        safe_absolute_path(&input.target, "bootc filesystem target")?
    };

    let mut argv = vec![
        "bootc".to_string(),
        "install".to_string(),
        subcommand.clone(),
        "--source-imgref".to_string(),
        source_imgref.clone(),
        "--target-imgref".to_string(),
        target_imgref,
    ];
    if subcommand == "to-filesystem" {
        // `to-filesystem` writes into an already-prepared mountpoint, so
        // bootc offers no block-setup knob there. TPM2-bound LUKS is a
        // bootc block-setup, so it cannot be honored here — refuse it
        // rather than silently installing plaintext. Passphrase LUKS is
        // the opposite shape: the installer provisioned the encrypted
        // target itself before this plan runs, and bootc needs no
        // block-setup (and gets none) for it.
        if encryption == "tpm2" {
            return Err(
                "encryption unsupported for bootc to-filesystem installs: TPM2 encryption requires a to-disk install."
                    .to_string(),
            );
        }
        argv.push("--acknowledge-destructive".to_string());
        if input.skip_finalize {
            argv.push("--skip-finalize".to_string());
        }
        if input.root_subvolume {
            argv.push("--karg=rootflags=subvol=@".to_string());
        }
        if input.root_kargs.len() > 8 {
            return Err("too many kernel arguments for a filesystem install.".to_string());
        }
        for karg in &input.root_kargs {
            argv.push(format!("--karg={}", safe_karg(karg)?));
        }
    } else {
        // Passphrase LUKS is provisioned by the installer, never by a
        // bootc block-setup; pairing it with to-disk would either ignore
        // the requested encryption or double-provision the disk.
        if encryption == "passphrase" {
            return Err(
                "encryption unsupported for bootc to-disk installs: passphrase encryption is provisioned by the installer; it is not a bootc block-setup."
                    .to_string(),
            );
        }
        argv.extend(["--filesystem".to_string(), "btrfs".to_string()]);
        // The requested encryption mode is always explicit on the bootc
        // command line: `direct` for plaintext, `tpm2-luks` for TPM2-bound
        // LUKS. Plaintext is therefore a deliberate choice, never a silent
        // fallback when encryption was requested.
        match encryption.as_str() {
            "" | "none" => {
                argv.extend(["--block-setup".to_string(), "direct".to_string()]);
            }
            "tpm2" => {
                argv.extend(["--block-setup".to_string(), "tpm2-luks".to_string()]);
            }
            _ => unreachable!("encryption modes are validated above"),
        }
        if input.wipe {
            argv.push("--wipe".to_string());
        }
    }
    if input.skip_fetch_check && !argv.iter().any(|arg| arg == "--skip-fetch-check") {
        argv.push("--skip-fetch-check".to_string());
    }
    argv.push(target.clone());

    Ok(BootcInstallPlan {
        subcommand,
        argv,
        target,
        destructive: true,
        // --skip-fetch-check bypasses the reachability preflight only; a
        // docker:// source still needs the network when bootc executes.
        requires_network: source_imgref.starts_with("docker://"),
        executor: "kyth-installerd",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_fetch_check_runs_preflight_instead_of_skipping() {
        // The riskiest default, pinned: an absent key must fail fast at
        // validation, not mid-install. `true` stays an explicit opt-in.
        let input: BootcInstallInput = serde_json::from_str(
            r#"{"subcommand":"to-disk","source_imgref":"docker://ghcr.io/kyth-os/kyth:latest","target_imgref":"ghcr.io/kyth-os/kyth:latest","target":"/dev/sda"}"#,
        )
        .expect("minimal input deserializes");
        assert!(!input.skip_fetch_check);
        let plan = build_plan(input).expect("plan validates");
        assert!(
            !plan.argv.iter().any(|arg| arg == "--skip-fetch-check"),
            "preflight must run when the key is omitted"
        );
    }

    fn input(subcommand: &str) -> BootcInstallInput {
        BootcInstallInput {
            subcommand: subcommand.to_string(),
            source_imgref: "docker://ghcr.io/kyth-os/kyth:latest".to_string(),
            target_imgref: "ghcr.io/kyth-os/kyth:latest".to_string(),
            target: "/dev/sda".to_string(),
            skip_fetch_check: true,
            skip_finalize: false,
            root_subvolume: false,
            wipe: false,
            encryption: "none".to_string(),
            tpm_recovery_ack: false,
            root_kargs: Vec::new(),
        }
    }

    #[test]
    fn raw_registry_source_is_normalized_for_bootc_transport() {
        let source = "ghcr.io/kyth-os/kyth@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let plan = build_plan(BootcInstallInput {
            source_imgref: source.to_string(),
            ..input("to-disk")
        })
        .expect("pinned registry source should validate");

        assert!(plan.argv.windows(2).any(|pair| {
            pair[0] == "--source-imgref" && pair[1] == format!("docker://{source}")
        }));
        assert!(plan.requires_network);
    }

    #[test]
    fn builds_disk_install_without_arbitrary_flags() {
        let plan = build_plan(BootcInstallInput {
            wipe: true,
            ..input("to-disk")
        })
        .expect("disk plan should validate");
        assert_eq!(plan.argv[..3], ["bootc", "install", "to-disk"]);
        assert!(plan
            .argv
            .windows(2)
            .any(|pair| pair == ["--filesystem", "btrfs"]));
        assert!(plan.argv.iter().any(|arg| arg == "--wipe"));
        assert!(plan.requires_network);
    }

    #[test]
    fn builds_filesystem_install_with_safe_bootc_flags() {
        let plan = build_plan(BootcInstallInput {
            target: "/mnt/kyth".to_string(),
            skip_fetch_check: false,
            skip_finalize: true,
            root_subvolume: true,
            ..input("to-filesystem")
        })
        .expect("filesystem plan should validate");
        assert!(plan
            .argv
            .iter()
            .any(|arg| arg == "--acknowledge-destructive"));
        assert!(plan.argv.iter().any(|arg| arg == "--skip-finalize"));
        assert!(plan
            .argv
            .iter()
            .any(|arg| arg == "--karg=rootflags=subvol=@"));
        assert!(plan.requires_network);
    }

    #[test]
    fn rejects_unsafe_targets_and_references() {
        for target in ["../../etc", "relative", "/mnt/with space"] {
            let error = build_plan(BootcInstallInput {
                target: target.to_string(),
                ..input("to-filesystem")
            })
            .expect_err("unsafe target must fail");
            assert!(error.contains("target"), "{error}");
        }
        let error = build_plan(BootcInstallInput {
            source_imgref: "docker://example/$(touch /tmp/pwned)".to_string(),
            ..input("to-disk")
        })
        .expect_err("unsafe image reference must fail");
        assert!(error.contains("image reference"));
    }

    #[test]
    fn encryption_defaults_to_explicit_plaintext_block_setup() {
        let plan = build_plan(input("to-disk")).expect("disk plan should validate");
        assert!(plan
            .argv
            .windows(2)
            .any(|pair| pair == ["--block-setup", "direct"]));
        assert!(!plan
            .argv
            .windows(2)
            .any(|pair| pair == ["--block-setup", "tpm2-luks"]));
    }

    #[test]
    fn tpm2_encryption_selects_tpm2_luks_block_setup() {
        let plan = build_plan(BootcInstallInput {
            encryption: "tpm2".to_string(),
            tpm_recovery_ack: true,
            wipe: true,
            ..input("to-disk")
        })
        .expect("tpm2 disk plan should validate");
        assert!(plan
            .argv
            .windows(2)
            .any(|pair| pair == ["--block-setup", "tpm2-luks"]));
        assert!(!plan
            .argv
            .windows(2)
            .any(|pair| pair == ["--block-setup", "direct"]));
    }

    #[test]
    fn unknown_encryption_fails_closed_instead_of_plaintext() {
        for mode in ["luks", "tpm", "aes-256", "yes"] {
            let error = build_plan(BootcInstallInput {
                encryption: mode.to_string(),
                ..input("to-disk")
            })
            .expect_err("unknown encryption mode must fail closed");
            assert!(
                error.contains("encryption unsupported"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn tpm2_without_recovery_ack_fails_closed() {
        let error = build_plan(BootcInstallInput {
            encryption: "tpm2".to_string(),
            ..input("to-disk")
        })
        .expect_err("tpm2 without a recovery plan must fail closed");
        // The message must stay honest: a one-time recovery key is
        // generated during the install and shown exactly once, never
        // stored — the acknowledgement is about recording it.
        assert!(
            error.contains("TPM unlock is bound to this machine."),
            "unexpected error: {error}"
        );
        assert!(
            error.contains("a one-time recovery key will be generated and shown exactly once"),
            "unexpected error: {error}"
        );
        assert!(
            error.contains("Confirm you will record the recovery key before installing."),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn filesystem_install_cannot_honor_encryption() {
        let error = build_plan(BootcInstallInput {
            encryption: "tpm2".to_string(),
            tpm_recovery_ack: true,
            target: "/mnt/kyth".to_string(),
            ..input("to-filesystem")
        })
        .expect_err("to-filesystem cannot honor TPM2 encryption");
        assert!(
            error.contains("encryption unsupported"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn passphrase_filesystem_install_is_provisioned_not_block_setup() {
        // Passphrase LUKS is provisioned by the installer before bootc
        // runs: the plan must validate without any recovery ack, carry no
        // --block-setup at all, and carry the executor's LUKS kargs.
        let plan = build_plan(BootcInstallInput {
            encryption: "passphrase".to_string(),
            target: "/run/kyth-installer/alongside-target".to_string(),
            root_kargs: vec![
                "rd.luks.uuid=1234abcd-1234-1234-1234-1234abcdef01".to_string(),
                "root=/dev/mapper/cryptroot".to_string(),
            ],
            ..input("to-filesystem")
        })
        .expect("passphrase filesystem plan should validate");
        assert!(
            !plan.argv.iter().any(|arg| arg == "--block-setup"),
            "provisioned LUKS must not gain a bootc block-setup: {:?}",
            plan.argv
        );
        assert!(plan
            .argv
            .iter()
            .any(|arg| arg == "--karg=rd.luks.uuid=1234abcd-1234-1234-1234-1234abcdef01"));
        assert!(plan
            .argv
            .iter()
            .any(|arg| arg == "--karg=root=/dev/mapper/cryptroot"));
    }

    #[test]
    fn passphrase_disk_install_fails_closed() {
        let error = build_plan(BootcInstallInput {
            encryption: "passphrase".to_string(),
            wipe: true,
            ..input("to-disk")
        })
        .expect_err("passphrase is not a bootc block-setup");
        assert!(
            error.contains("provisioned by the installer"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn root_kargs_are_validated_before_they_reach_bootc() {
        for karg in [
            "root=/dev/mapper/cryptroot; rm -rf /",
            "root=/dev/mapper/crypt root",
            "",
        ] {
            let error = build_plan(BootcInstallInput {
                target: "/mnt/kyth".to_string(),
                root_kargs: vec![karg.to_string()],
                ..input("to-filesystem")
            })
            .expect_err("unsafe karg must fail closed");
            assert!(
                error.contains("kernel argument"),
                "unexpected error for {karg:?}: {error}"
            );
        }
    }
}
