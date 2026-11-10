//! KythOS-signed update manifest verification for the runtime updaters.
//!
//! Implements the updater signature-verification decision (approved
//! 2026-10-19, docs/updater-signing.md). Today both runtime updaters
//! (rclone, GE-Proton) verify downloads against a checksum fetched from
//! the same release as the artifact itself, which proves transport
//! integrity but not authenticity: a compromised upstream release
//! replaces the file and its checksum together. The fix is a small
//! manifest, signed offline with the KythOS updater signing key, that
//! approves a specific (component, version, artifact, digest) tuple.
//! The updaters refuse — fail closed — unless the update they are about
//! to install is approved by a manifest whose OpenPGP signature verifies
//! against the KythOS signing primary key baked into the image.
//!
//! Trust model (mirrors the decision):
//!   * The image carries only PUBLIC key material: the trust anchor at
//!     [`DEFAULT_KEYRING_PATH`] is the primary key certificate(s).
//!   * The current certificate (primary + its current signing subkeys)
//!     is published next to the manifest as [`KEYS_FILENAME`]. A fetched
//!     certificate is trusted only when its primary key fingerprint
//!     matches a baked-in anchor — so a signing-subkey rotation needs
//!     no image update (publish the amended certificate), while a new
//!     primary must ride out in an image update. The anchor file may
//!     hold several certificates so an old and a new primary can
//!     overlap during a primary rotation.
//!   * Signing is offline and manual; nothing automated can sign. This
//!     module is verify-only.
//!   * Any failure — missing/unparseable key, missing manifest,
//!     missing or invalid signature, no manifest entry for the resolved
//!     version, digest mismatch — is an error, and the callers refuse
//!     the install and keep the current version.
//!   * Replay bound: a valid signature proves a manifest is genuine,
//!     not that it is current — an old manifest stays validly signed
//!     forever, so a stale mirror or a replayed response could roll a
//!     client back to a vulnerable version whose digest still verifies.
//!     Each updater therefore keeps a floor file recording the `issued`
//!     timestamp of the newest manifest it has ever accepted, and
//!     refuses any manifest issued earlier than that floor. The bound
//!     is the manifest's own signed timestamp compared against local
//!     state; the client wall clock is never consulted. A rollback is
//!     still possible exactly as documented: publish a *freshly issued*
//!     manifest that approves the older version.
//!
//! Until a real public key replaces the shipped placeholder anchor, the
//! anchor contains no key material and every gated update is refused
//! with an explicit "signing key not installed yet" error. That is the
//! intended placeholder behaviour, not a bypass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;
use serde::Deserialize;

use super::release_fetch::{digest_file_hex, download_file, MAX_CHECKSUM_BYTES};

pub const COMPONENT_RCLONE: &str = "rclone";
pub const COMPONENT_GE_PROTON: &str = "ge-proton";

/// File names published on the KythOS public release channel (the same
/// R2 bucket `release_publish` serves ISO metadata from).
pub const MANIFEST_FILENAME: &str = "kyth-updater-manifest.json";
pub const KEYS_FILENAME: &str = "kyth-updater-keys.asc";

/// Image-baked trust anchor: OpenPGP public certificate(s) of the
/// KythOS updater signing primary key(s). Installed from
/// `build_files/config/updater-signing-keys.asc` by the branding
/// fragment `99-updater-signing-key.sh`.
pub const DEFAULT_KEYRING_PATH: &str = "/usr/share/kyth/updater-signing-keys.asc";

pub const KEYRING_PATH_ENV: &str = "KYTH_UPDATER_KEYRING_PATH";
pub const MANIFEST_URL_ENV: &str = "KYTH_UPDATER_MANIFEST_URL";
pub const SIGNATURE_URL_ENV: &str = "KYTH_UPDATER_MANIFEST_SIGNATURE_URL";
pub const KEYS_URL_ENV: &str = "KYTH_UPDATER_KEYS_URL";
pub const FLOOR_PATH_ENV: &str = "KYTH_UPDATER_FLOOR_PATH";

/// Replay-floor state file name, kept in each updater's own state
/// directory (see [`floor_state_path`]). The file holds one line: the
/// `issued` timestamp, as unix seconds, of the newest signed manifest
/// that updater has accepted.
pub const FLOOR_FILENAME: &str = "updater-manifest-floor";

/// Only manifest schema this build understands. Unknown schemas fail
/// closed: a future format must not be half-interpreted by old images.
pub const SUPPORTED_MANIFEST_SCHEMA: u32 = 1;

pub fn default_manifest_url() -> String {
    format!(
        "{}/{MANIFEST_FILENAME}",
        crate::release_publish::PUBLIC_ASSET_BASE_URL
    )
}

pub fn default_keys_url() -> String {
    format!(
        "{}/{KEYS_FILENAME}",
        crate::release_publish::PUBLIC_ASSET_BASE_URL
    )
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

pub fn keyring_path() -> PathBuf {
    PathBuf::from(env_or(KEYRING_PATH_ENV, DEFAULT_KEYRING_PATH))
}

pub fn manifest_url() -> String {
    env_or(MANIFEST_URL_ENV, &default_manifest_url())
}

pub fn signature_url() -> String {
    let manifest = manifest_url();
    env_or(SIGNATURE_URL_ENV, &format!("{manifest}.asc"))
}

pub fn keys_url() -> String {
    env_or(KEYS_URL_ENV, &default_keys_url())
}

/// Where one updater's replay-floor state lives. Each updater writes
/// only inside state it already owns: GE-Proton's unit grants it
/// `/var/lib/kyth/proton-cachyos` (its `StateDirectory`, the one path
/// writable under its `ProtectSystem=strict` sandbox), and the rclone
/// updater runs unsandboxed as root via sudo, so it gets a sibling
/// directory. No shared location is writable by both, and none is
/// needed: each updater only ever approves its own component, so a
/// per-updater floor gives each component the full guarantee — a
/// manifest older than the newest that component's updater has
/// accepted is refused. `KYTH_UPDATER_FLOOR_PATH` overrides the whole
/// path (tests, operator recovery).
pub fn floor_state_path(component: &str) -> PathBuf {
    if let Some(path) = std::env::var(FLOOR_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return PathBuf::from(path);
    }
    let dir = match component {
        COMPONENT_GE_PROTON => PathBuf::from("/var/lib/kyth/proton-cachyos"),
        COMPONENT_RCLONE => PathBuf::from("/var/lib/kyth/rclone-update"),
        other => PathBuf::from(format!("/var/lib/kyth/{other}")),
    };
    dir.join(FLOOR_FILENAME)
}

/// One approved update tuple from the signed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApprovedUpdate {
    pub component: String,
    pub version: String,
    pub artifact: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub sha512: Option<String>,
}

impl ApprovedUpdate {
    /// The manifest-pinned digest for `algorithm` ("sha256"/"sha512"),
    /// normalized to lowercase hex. A manifest entry that lacks the
    /// digest an updater needs is a refusal, not a skip: the signature
    /// only vouches for values actually present.
    pub fn expected_digest(&self, algorithm: &str) -> Result<String, String> {
        let raw = match algorithm {
            "sha256" => self.sha256.as_deref(),
            "sha512" => self.sha512.as_deref(),
            other => {
                return Err(format!(
                    "unsupported digest algorithm for manifest check: {other}"
                ))
            }
        };
        let digest = raw
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "signed updater manifest entry for {} {} ({}) has no {algorithm} digest",
                    self.component, self.version, self.artifact
                )
            })?;
        let expected_len = if algorithm == "sha256" { 64 } else { 128 };
        if digest.len() != expected_len || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "signed updater manifest entry for {} {} ({}) has a malformed {algorithm} digest",
                self.component, self.version, self.artifact
            ));
        }
        Ok(digest.to_ascii_lowercase())
    }
}

/// The signed manifest document. The signature covers the exact bytes
/// of the JSON file as published; parsing happens only after the
/// signature verifies, so field handling never has to be defensive
/// about unsigned input beyond ordinary shape errors.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UpdateManifest {
    pub schema: u32,
    #[serde(default)]
    pub issued: String,
    pub updates: Vec<ApprovedUpdate>,
}

impl UpdateManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let manifest: UpdateManifest = serde_json::from_slice(bytes)
            .map_err(|error| format!("signed updater manifest is not valid JSON: {error}"))?;
        if manifest.schema != SUPPORTED_MANIFEST_SCHEMA {
            return Err(format!(
                "signed updater manifest schema {} is not supported by this build (expected {SUPPORTED_MANIFEST_SCHEMA})",
                manifest.schema
            ));
        }
        Ok(manifest)
    }

    /// The manifest's `issued` timestamp as unix seconds — the
    /// monotonic value the replay floor compares. A manifest without a
    /// usable `issued` is refused: the field has been emitted by the
    /// generator since the format was introduced, and no signed
    /// manifest was ever published without one (the trust anchor is
    /// still a placeholder, so no real manifest exists yet), so
    /// requiring it strands nothing. Without it a replayed manifest
    /// cannot be told apart from a current one.
    pub fn issued_unix(&self) -> Result<i64, String> {
        let issued = self.issued.trim();
        if issued.is_empty() {
            return Err(
                "signed updater manifest has no 'issued' timestamp; manifests without one \
                 are refused so a replayed manifest cannot pass as current — regenerate \
                 and re-sign the manifest (see docs/updater-signing.md)"
                    .to_string(),
            );
        }
        parse_issued_unix(issued).ok_or_else(|| {
            format!(
                "signed updater manifest 'issued' timestamp {issued:?} is not a valid \
                 RFC 3339 timestamp; refusing it (see docs/updater-signing.md)"
            )
        })
    }

    /// Exactly one entry must approve the (component, version, artifact)
    /// being installed. Zero matches means the update was never approved;
    /// duplicates mean the manifest itself is ambiguous. Both refuse.
    pub fn find(
        &self,
        component: &str,
        version: &str,
        artifact: &str,
    ) -> Result<ApprovedUpdate, String> {
        let mut matches = self
            .updates
            .iter()
            .filter(|entry| {
                entry.component == component
                    && entry.version == version
                    && entry.artifact == artifact
            })
            .cloned();
        match (matches.next(), matches.next()) {
            (Some(entry), None) => Ok(entry),
            (None, _) => Err(format!(
                "signed updater manifest does not approve {component} {version} ({artifact})"
            )),
            (Some(_), Some(_)) => Err(format!(
                "signed updater manifest approves {component} {version} ({artifact}) more than once"
            )),
        }
    }
}

/// Days from 1970-01-01 for a proleptic Gregorian date
/// (Howard Hinnant's days-from-civil algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400; // [0, 399]
    let month_prime = i64::from((month + 9) % 12); // Mar=0 .. Feb=11
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Strict RFC 3339 timestamp → unix seconds, with no date crate: this
/// crate deliberately carries no time dependency for one comparison.
/// Accepts exactly `YYYY-MM-DDTHH:MM:SS` with an optional fractional
/// part and a `Z` or `±HH:MM` offset — the shape the manifest
/// generator emits (`%Y-%m-%dT%H:%M:%SZ`) plus sane variants. Anything
/// else returns `None`; callers fail closed on `None`. A leap-second
/// `:60` is clamped to `:59` (unix time cannot represent it and the
/// floor only needs second-level ordering).
fn parse_issued_unix(issued: &str) -> Option<i64> {
    let bytes = issued.as_bytes();
    let digit = |index: usize| -> Option<i64> {
        bytes
            .get(index)
            .filter(|byte| byte.is_ascii_digit())
            .map(|byte| i64::from(byte - b'0'))
    };
    let two_digits = |index: usize| -> Option<i64> { Some(digit(index)? * 10 + digit(index + 1)?) };
    let year = digit(0)? * 1000 + digit(1)? * 100 + digit(2)? * 10 + digit(3)?;
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let month = two_digits(5)?;
    let day = two_digits(8)?;
    if !matches!(bytes.get(10), Some(b'T') | Some(b't')) {
        return None;
    }
    if bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') {
        return None;
    }
    let hour = two_digits(11)?;
    let minute = two_digits(14)?;
    let second = two_digits(17)?;
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return None;
        }
    }
    let offset_seconds: i64 = match bytes.get(index) {
        Some(b'Z') | Some(b'z') => {
            index += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            if bytes.get(index + 3) != Some(&b':') {
                return None;
            }
            let offset_hour = two_digits(index + 1)?;
            let offset_minute = two_digits(index + 4)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            index += 6;
            let magnitude = offset_hour * 3600 + offset_minute * 60;
            if *sign == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };
    if index != bytes.len() {
        return None;
    }
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let (month, day) = (month as u32, day as u32);
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second.min(59) - offset_seconds)
}

/// Read the recorded floor. A missing file is the first-run state
/// (`Ok(None)`); any other read failure is an error — guessing at the
/// floor would quietly reopen the replay window.
fn read_floor(path: &Path) -> Result<Option<i64>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "cannot read the updater manifest floor state at {}: {error}",
                path.display()
            ))
        }
    };
    let text = raw.trim();
    // Canonical form only: decimal digits. A torn or hand-mangled file
    // fails closed rather than being interpreted leniently.
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "updater manifest floor state at {} is corrupt (expected a single unix \
             timestamp, found {text:?}); refusing updates so replay protection stays \
             intact. To re-baseline the floor, delete {} and re-run the updater: the \
             next validly signed manifest will be accepted and recorded",
            path.display(),
            path.display()
        ));
    }
    text.parse::<i64>().map(Some).map_err(|error| {
        format!(
            "updater manifest floor state at {} is corrupt ({error}); refusing updates. \
             To re-baseline the floor, delete {} and re-run the updater",
            path.display(),
            path.display()
        )
    })
}

/// Persist a new floor atomically: write a sibling temp file, fsync,
/// rename over the floor file, so a crash or power loss can never
/// leave a torn floor behind (a torn file would read as corrupt and
/// refuse updates until an operator re-baselines it).
fn record_floor(path: &Path, issued_unix: i64) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "cannot create the updater manifest floor directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| FLOOR_FILENAME.to_string());
    let temp = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let write = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(format!("{issued_unix}\n").as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)?;
        // Best-effort directory fsync so the rename itself is durable.
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    if let Err(error) = write {
        let _ = std::fs::remove_file(&temp);
        return Err(format!(
            "cannot record the updater manifest floor at {}: {error}",
            path.display()
        ));
    }
    Ok(())
}

/// The replay bound, applied to every verified manifest before it may
/// approve anything: the manifest's `issued` must be at least the
/// floor (the newest `issued` this updater has ever accepted), and a
/// strictly newer manifest advances the floor *before* the caller acts
/// on it — so once this system has seen a newer signed manifest, older
/// ones are dead even if the newer one did not approve the version
/// being resolved. Acceptance without recording would silently drop
/// the protection for the next run, so a floor that cannot be recorded
/// is a refusal, not a warning. Equal is accepted without a write:
/// re-checking the same manifest is the normal idempotent path.
pub fn check_and_record_floor(path: &Path, manifest: &UpdateManifest) -> Result<(), String> {
    let issued_unix = manifest.issued_unix()?;
    match read_floor(path)? {
        None => record_floor(path, issued_unix),
        Some(floor) if issued_unix < floor => Err(format!(
            "signed updater manifest issued {:?} (unix {issued_unix}) is older than the \
             newest manifest this updater has already accepted (floor: unix {floor}); \
             refusing a replayed or rolled-back manifest. To roll back deliberately, \
             publish a freshly generated manifest approving the older version instead \
             (see docs/updater-signing.md)",
            manifest.issued.trim()
        )),
        Some(floor) if issued_unix == floor => Ok(()),
        Some(_) => record_floor(path, issued_unix),
    }
}

/// Parse every OpenPGP public certificate in a keyring blob (armored
/// or binary, one or several certificates). Unparseable entries are
/// skipped: callers fail closed when the usable set is empty, and one
/// corrupt entry must not hide a good one during a key overlap window.
/// Secret keys are never accepted as trust material and are dropped.
///
/// Parse armored certificates. A keyring file may carry several
/// certificates in one armor block (a single multi-key export) or as
/// several concatenated armor blocks (keyring-style append, which is
/// how an overlap anchor is written) — rPGP's armor iterator covers a
/// single block, so split blocks and parse each.
fn parse_armored_certs(text: &str) -> Vec<SignedPublicKey> {
    const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    let mut certs = Vec::new();
    for piece in text.split(BEGIN).skip(1) {
        let block = format!("{BEGIN}{piece}");
        if let Ok((iter, _headers)) =
            SignedPublicKey::from_armor_many(std::io::Cursor::new(block.into_bytes()))
        {
            certs.extend(iter.flatten());
        }
    }
    certs
}

fn parse_certs(bytes: &[u8]) -> Vec<SignedPublicKey> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(bytes);
    if text.contains("-----BEGIN PGP") {
        return parse_armored_certs(&text);
    }
    let Ok(iter) = SignedPublicKey::from_bytes_many(std::io::Cursor::new(bytes.to_vec())) else {
        return Vec::new();
    };
    iter.flatten().collect()
}

/// Certificates from the published key file whose primary key is one of
/// the baked-in anchors. The anchor pins the primary's fingerprint; the
/// fetched certificate supplies the primary's current signing subkeys,
/// which is what makes subkey rotation possible without an image
/// update. Anything else in the fetched file is ignored.
fn trusted_certs<'a>(
    anchors: &[SignedPublicKey],
    fetched: &'a [SignedPublicKey],
) -> Vec<&'a SignedPublicKey> {
    fetched
        .iter()
        .filter(|cert| {
            anchors
                .iter()
                .any(|anchor| anchor.fingerprint() == cert.fingerprint())
        })
        .collect()
}

/// Parse a detached signature (armored `.asc` as published, or raw
/// binary). Anything unparseable is an error: a missing or mangled
/// signature is a refusal, never a skip.
fn parse_signature(bytes: &[u8]) -> Result<DetachedSignature, String> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("-----BEGIN PGP") {
        let (signature, _) =
            DetachedSignature::from_armor_single(std::io::Cursor::new(bytes.to_vec()))
                .map_err(|error| format!("updater manifest signature is unparseable: {error}"))?;
        return Ok(signature);
    }
    DetachedSignature::from_bytes(std::io::Cursor::new(bytes.to_vec()))
        .map_err(|error| format!("updater manifest signature is unparseable: {error}"))
}

/// True when `signature` validates over `data` under `cert`'s primary
/// key or any of its public subkeys. The caller must already have
/// checked the certificate's self-signatures (`verify_bindings`): a
/// subkey only counts when the trusted primary actually bound it.
fn verifies_under(cert: &SignedPublicKey, signature: &DetachedSignature, data: &[u8]) -> bool {
    if signature.verify(cert, data).is_ok() {
        return true;
    }
    cert.public_subkeys
        .iter()
        .any(|subkey| signature.verify(subkey, data).is_ok())
}

/// Pure verification core: given the baked anchor keyring bytes, the
/// published key file bytes, and the manifest + detached signature
/// bytes, return the parsed manifest only if the signature verifies
/// under a certificate whose primary matches an anchor. Every other
/// outcome is an error (fail closed).
pub fn verify_signed_manifest(
    anchor_keyring: &[u8],
    published_keys: &[u8],
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<UpdateManifest, String> {
    let anchors = parse_certs(anchor_keyring);
    if anchors.is_empty() {
        return Err(
            "no KythOS updater signing key is installed yet (the image still carries the \
             placeholder trust anchor), so no update can be verified"
                .to_string(),
        );
    }
    let fetched = parse_certs(published_keys);
    let trusted = trusted_certs(&anchors, &fetched);
    if trusted.is_empty() {
        return Err(
            "the published updater key file contains no certificate for the KythOS updater \
             signing key trusted by this image"
                .to_string(),
        );
    }
    let signature = parse_signature(signature_bytes)?;
    // A certificate counts only with intact self-signatures: the
    // subkey binding signatures are what stop a substituted subkey
    // riding on the (public) primary key. Then the detached signature
    // itself must validate under the primary or a bound subkey —
    // rPGP's signature check also enforces issuer identity and hash
    // strength.
    let verified = trusted.iter().any(|cert| {
        cert.verify_bindings().is_ok() && verifies_under(cert, &signature, manifest_bytes)
    });
    if !verified {
        return Err(
            "manifest signature did not validate against the trusted KythOS updater signing key"
                .to_string(),
        );
    }
    UpdateManifest::parse(manifest_bytes)
}

/// Full updater gate: fetch the signed manifest, its detached
/// signature, and the published key file; verify the signature against
/// the image-baked trust anchor; apply the replay floor
/// ([`check_and_record_floor`]); return the single manifest entry
/// approving (component, version, artifact). Any failure is an error
/// and the caller must refuse the install.
pub fn approve_update(
    run: &dyn for<'x> Fn(&'x [String], u64) -> Option<(i32, String)>,
    work: &Path,
    component: &str,
    version: &str,
    artifact: &str,
) -> Result<ApprovedUpdate, String> {
    let anchor_path = keyring_path();
    let anchor_bytes = std::fs::read(&anchor_path).map_err(|error| {
        format!(
            "cannot read the KythOS updater signing trust anchor at {}: {error}",
            anchor_path.display()
        )
    })?;
    if parse_certs(&anchor_bytes).is_empty() {
        return Err(
            "no KythOS updater signing key is installed yet (the image still carries the \
             placeholder trust anchor), so no update can be verified"
                .to_string(),
        );
    }
    let manifest_name = MANIFEST_FILENAME;
    let signature_name = format!("{MANIFEST_FILENAME}.asc");
    let keys_name = KEYS_FILENAME;
    let manifest_dest = work.join(&manifest_name);
    let signature_dest = work.join(&signature_name);
    let keys_dest = work.join(&keys_name);
    let headers = BTreeMap::new();
    for (url, dest) in [
        (manifest_url(), &manifest_dest),
        (signature_url(), &signature_dest),
        (keys_url(), &keys_dest),
    ] {
        download_file(run, &url, dest, &headers, 60, MAX_CHECKSUM_BYTES)
            .map_err(|error| format!("cannot fetch the signed updater manifest set: {error}"))?;
    }
    let manifest_bytes = std::fs::read(&manifest_dest)
        .map_err(|error| format!("cannot read the downloaded updater manifest: {error}"))?;
    let signature_bytes = std::fs::read(&signature_dest)
        .map_err(|error| format!("cannot read the downloaded manifest signature: {error}"))?;
    let published_keys = std::fs::read(&keys_dest)
        .map_err(|error| format!("cannot read the published updater key file: {error}"))?;
    let manifest = verify_signed_manifest(
        &anchor_bytes,
        &published_keys,
        &manifest_bytes,
        &signature_bytes,
    )?;
    // The signature proves this manifest is genuine, not that it is
    // current: bind it to the newest manifest this updater has already
    // accepted before it may approve anything.
    check_and_record_floor(&floor_state_path(component), &manifest)?;
    manifest.find(component, version, artifact)
}

/// Second half of the gate: the downloaded artifact must hash to the
/// digest the signed manifest pinned for it. This runs IN ADDITION TO
/// the updaters' existing upstream checksum verification — the upstream
/// checksum proves the download matches the release page; this proves
/// the artifact is the one the KythOS signing key approved.
pub fn verify_artifact_matches(
    entry: &ApprovedUpdate,
    algorithm: &str,
    artifact_path: &Path,
) -> Result<(), String> {
    let expected = entry.expected_digest(algorithm)?;
    let actual = digest_file_hex(algorithm, artifact_path)?;
    if actual != expected {
        return Err(format!(
            "{algorithm} digest of {} does not match the signed updater manifest: expected {expected}, got {actual}",
            artifact_path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{
        ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
    };
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::types::{KeyVersion, Password};
    use rand::SeedableRng;

    const MANIFEST_JSON: &[u8] = br#"{
        "schema": 1,
        "issued": "2026-10-19T00:00:00Z",
        "updates": [
            {"component": "rclone", "version": "v1.68.2",
             "artifact": "rclone-v1.68.2-linux-amd64.zip",
             "sha256": "abababababababababababababababababababababababababababababababab"},
            {"component": "ge-proton", "version": "GE-Proton10-15",
             "artifact": "GE-Proton10-15-x86_64.tar.gz",
             "sha512": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}
        ]
    }"#;

    /// Throwaway secret key in the approved layout — a primary plus
    /// `signing_subkeys` signing subkeys — generated inside the test
    /// run and discarded with it. Never production key material.
    fn generate_secret(signing_subkeys: usize, seed: u64) -> SignedSecretKey {
        // Distinct seeds per test key: Ed25519 generation is
        // deterministic in the RNG stream, so reusing one seed would
        // produce byte-identical "different" keys.
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .version(KeyVersion::V4)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("KythOS Updater Signing (throwaway test key)".to_string());
        for _ in 0..signing_subkeys {
            let subkey = SubkeyParamsBuilder::default()
                .version(KeyVersion::V4)
                .key_type(KeyType::Ed25519)
                .can_sign(true)
                .build()
                .expect("build throwaway subkey params");
            params.subkey(subkey);
        }
        params
            .build()
            .expect("build throwaway key params")
            .generate(&mut rng)
            .expect("generate throwaway test key")
    }

    fn armored(secret: &SignedSecretKey) -> Vec<u8> {
        secret
            .to_public_key()
            .to_armored_bytes(ArmorOptions::default())
            .expect("export throwaway test cert")
    }

    /// Detached armored signature over `data`, made by the `nth`
    /// secret signing subkey (0-based) of `secret`.
    fn sign_with_subkey(secret: &SignedSecretKey, nth: usize, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5349_4755_4B59);
        let subkey = secret
            .secret_subkeys
            .get(nth)
            .expect("test key has the requested signing subkey");
        DetachedSignature::sign_binary_data(
            &mut rng,
            &subkey.key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            std::io::Cursor::new(data.to_vec()),
        )
        .expect("sign test data")
        .to_armored_bytes(ArmorOptions::default())
        .expect("armor test signature")
    }

    #[test]
    fn valid_signature_unlocks_matching_entry() {
        let cert = generate_secret(1, 0xA11CE);
        let keyring = armored(&cert);
        let signature = sign_with_subkey(&cert, 0, MANIFEST_JSON);
        let manifest = verify_signed_manifest(&keyring, &keyring, MANIFEST_JSON, &signature)
            .expect("valid signature must verify");
        let entry = manifest
            .find("rclone", "v1.68.2", "rclone-v1.68.2-linux-amd64.zip")
            .expect("approved rclone entry must be found");
        assert_eq!(entry.component, COMPONENT_RCLONE);
        let proton = manifest
            .find(
                "ge-proton",
                "GE-Proton10-15",
                "GE-Proton10-15-x86_64.tar.gz",
            )
            .expect("approved GE-Proton entry must be found");
        assert_eq!(proton.component, COMPONENT_GE_PROTON);
    }

    #[test]
    fn tampered_manifest_is_refused() {
        let cert = generate_secret(1, 0xA11CE);
        let keyring = armored(&cert);
        let signature = sign_with_subkey(&cert, 0, MANIFEST_JSON);
        let mut tampered = MANIFEST_JSON.to_vec();
        tampered[20] ^= 0x01;
        let error = verify_signed_manifest(&keyring, &keyring, &tampered, &signature)
            .expect_err("a tampered manifest must not verify");
        assert!(error.contains("signature"), "unexpected error: {error}");
    }

    #[test]
    fn signature_from_unrelated_key_is_refused() {
        let trusted = generate_secret(1, 0xA11CE);
        let attacker = generate_secret(1, 0xBAD5EED);
        let keyring = armored(&trusted);
        // The attacker publishes their own certificate and signs with
        // it: cryptographically self-consistent, but the primary is
        // not the baked-in anchor, so it must be refused.
        let attacker_keyring = armored(&attacker);
        let signature = sign_with_subkey(&attacker, 0, MANIFEST_JSON);
        let error = verify_signed_manifest(&keyring, &attacker_keyring, MANIFEST_JSON, &signature)
            .expect_err("an unanchored primary must not verify");
        assert!(
            error.contains("no certificate"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn missing_signature_is_refused() {
        let cert = generate_secret(1, 0xA11CE);
        let keyring = armored(&cert);
        let error = verify_signed_manifest(&keyring, &keyring, MANIFEST_JSON, b"not a signature")
            .expect_err("garbage instead of a signature must not verify");
        assert!(!error.is_empty());
        let error = verify_signed_manifest(&keyring, &keyring, MANIFEST_JSON, b"")
            .expect_err("an absent signature must not verify");
        assert!(!error.is_empty());
    }

    #[test]
    fn placeholder_anchor_is_refused_with_named_reason() {
        let cert = generate_secret(1, 0xA11CE);
        let keyring = armored(&cert);
        let signature = sign_with_subkey(&cert, 0, MANIFEST_JSON);
        let placeholder: &[u8] = b"# KythOS updater signing keys\n\
            # PLACEHOLDER: no production key has been installed yet.\n";
        let error = verify_signed_manifest(placeholder, &keyring, MANIFEST_JSON, &signature)
            .expect_err("a placeholder anchor must refuse every update");
        assert!(
            error.contains("placeholder"),
            "error must name the placeholder state: {error}"
        );
        let error = verify_signed_manifest(b"", &keyring, MANIFEST_JSON, &signature)
            .expect_err("an empty anchor must refuse every update");
        assert!(error.contains("placeholder"), "unexpected error: {error}");
    }

    #[test]
    fn unapproved_version_is_refused() {
        let cert = generate_secret(1, 0xA11CE);
        let keyring = armored(&cert);
        let signature = sign_with_subkey(&cert, 0, MANIFEST_JSON);
        let manifest = verify_signed_manifest(&keyring, &keyring, MANIFEST_JSON, &signature)
            .expect("valid signature must verify");
        // Signature valid; approval absent. This is the fail-closed
        // path for a brand-new upstream release that no signed
        // manifest has approved yet.
        let error = manifest
            .find("rclone", "v9.99.9", "rclone-v9.99.9-linux-amd64.zip")
            .expect_err("an unapproved version must be refused");
        assert!(
            error.contains("does not approve"),
            "unexpected error: {error}"
        );
        let error = manifest
            .find(
                "ge-proton",
                "GE-Proton10-15",
                "GE-Proton10-15-aarch64.tar.gz",
            )
            .expect_err("an unapproved artifact name must be refused");
        assert!(error.contains("does not approve"));
    }

    #[test]
    fn rotated_signing_subkey_verifies_against_same_primary_anchor() {
        // Rotation semantics from the decision: the image anchors the
        // primary; any signing subkey bound to that primary is
        // accepted, so a fresh subkey verifies with no image change.
        let cert = generate_secret(2, 0xA11CE);
        let keyring = armored(&cert);
        let signature = sign_with_subkey(&cert, 1, MANIFEST_JSON);
        verify_signed_manifest(&keyring, &keyring, MANIFEST_JSON, &signature)
            .expect("a signature from the rotated-in subkey must verify");
    }

    #[test]
    fn overlapping_primaries_in_anchor_both_verify() {
        // Primary-rotation overlap: the anchor may carry the old and
        // the new primary at once; a manifest signed by either counts.
        let old = generate_secret(1, 0xA11CE);
        let new = generate_secret(1, 0xB0B);
        let mut anchor = armored(&old);
        anchor.extend_from_slice(&armored(&new));
        let published = armored(&new);
        let signature = sign_with_subkey(&new, 0, MANIFEST_JSON);
        verify_signed_manifest(&anchor, &published, MANIFEST_JSON, &signature)
            .expect("the incoming primary in an overlap anchor must verify");
    }

    #[test]
    fn artifact_digest_must_match_manifest_pin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact = dir.path().join("payload.bin");
        std::fs::write(&artifact, b"kyth test payload").expect("write artifact");
        let base = ApprovedUpdate {
            component: "rclone".to_string(),
            version: "v1.68.2".to_string(),
            artifact: "payload.bin".to_string(),
            sha256: None,
            sha512: None,
        };
        let real = digest_file_hex("sha256", &artifact).expect("hash artifact");
        let matching = ApprovedUpdate {
            sha256: Some(real),
            ..base.clone()
        };
        verify_artifact_matches(&matching, "sha256", &artifact).expect("matching digest must pass");
        let wrong = ApprovedUpdate {
            sha256: Some("00".repeat(32)),
            ..base.clone()
        };
        let error = verify_artifact_matches(&wrong, "sha256", &artifact)
            .expect_err("a mismatched digest must be refused");
        assert!(
            error.contains("does not match"),
            "unexpected error: {error}"
        );
        let error = verify_artifact_matches(&base, "sha256", &artifact)
            .expect_err("an entry without the needed digest must be refused");
        assert!(
            error.contains("no sha256 digest"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unknown_manifest_schema_is_refused() {
        let error = UpdateManifest::parse(br#"{"schema": 99, "updates": []}"#)
            .expect_err("an unknown schema must fail closed");
        assert!(error.contains("not supported"), "unexpected error: {error}");
    }

    /// A manifest carrying a given `issued`, for floor tests.
    fn manifest_issued(issued: &str) -> UpdateManifest {
        UpdateManifest::parse(
            format!(r#"{{"schema": 1, "issued": "{issued}", "updates": []}}"#).as_bytes(),
        )
        .expect("floor-test manifest must parse")
    }

    #[test]
    fn issued_timestamp_parser_is_strict() {
        // The generator's exact shape, plus sane RFC 3339 variants.
        assert_eq!(
            parse_issued_unix("2026-10-19T00:00:00Z"),
            Some(1_792_368_000)
        );
        assert_eq!(
            parse_issued_unix("2026-10-19T02:00:00+02:00"),
            Some(1_792_368_000)
        );
        assert_eq!(
            parse_issued_unix("2026-10-18T19:00:00-05:00"),
            Some(1_792_368_000)
        );
        assert_eq!(
            parse_issued_unix("2026-10-19T00:00:00.500Z"),
            Some(1_792_368_000)
        );
        assert_eq!(
            parse_issued_unix("2024-02-29T12:00:00Z"),
            Some(1_709_208_000)
        );
        // Everything malformed or out of range is refused, never
        // half-parsed into a comparison value.
        for bad in [
            "",
            "2026-10-19",
            "2026-10-19 00:00:00Z",
            "2026-10-19T00:00:00",
            "2026-10-19T00:00:00Zjunk",
            "2026-13-19T00:00:00Z",
            "2026-10-32T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2026-10-19T24:00:00Z",
            "2026-10-19T00:60:00Z",
            "2026-10-19T00:00:00+24:00",
            "not-a-timestamp",
        ] {
            assert_eq!(parse_issued_unix(bad), None, "must reject {bad:?}");
        }
    }

    #[test]
    fn manifest_without_issued_is_refused() {
        let manifest = UpdateManifest::parse(br#"{"schema": 1, "updates": []}"#)
            .expect("a manifest without 'issued' still parses");
        let error = manifest
            .issued_unix()
            .expect_err("a missing 'issued' must refuse at the floor");
        assert!(error.contains("no 'issued'"), "unexpected error: {error}");
        let manifest = manifest_issued("yesterday-ish");
        let error = manifest
            .issued_unix()
            .expect_err("an unparseable 'issued' must refuse at the floor");
        assert!(
            error.contains("not a valid RFC 3339"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn floor_records_first_acceptance_and_accepts_equal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state").join(FLOOR_FILENAME);
        let manifest = manifest_issued("2026-10-19T00:00:00Z");
        // First run: no state file, acceptance records the floor.
        check_and_record_floor(&path, &manifest).expect("first acceptance must succeed");
        assert_eq!(
            std::fs::read_to_string(&path).expect("floor file must exist"),
            "1792368000\n"
        );
        // Idempotent re-check of the same manifest: accepted, and the
        // floor is not rewritten.
        check_and_record_floor(&path, &manifest).expect("an equal manifest must be accepted");
        assert_eq!(
            std::fs::read_to_string(&path).expect("floor file must remain"),
            "1792368000\n"
        );
    }

    #[test]
    fn floor_advances_when_newer_manifest_arrives() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FLOOR_FILENAME);
        check_and_record_floor(&path, &manifest_issued("2026-10-19T00:00:00Z"))
            .expect("first acceptance must succeed");
        check_and_record_floor(&path, &manifest_issued("2026-11-02T09:30:00Z"))
            .expect("a newer manifest must be accepted");
        assert_eq!(
            std::fs::read_to_string(&path).expect("floor file must exist"),
            format!(
                "{}\n",
                parse_issued_unix("2026-11-02T09:30:00Z").expect("parse")
            )
        );
        // The temp sibling is consumed by the rename, never left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read state dir")
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp floor files left: {leftovers:?}");
    }

    #[test]
    fn replayed_manifest_is_refused_by_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FLOOR_FILENAME);
        check_and_record_floor(&path, &manifest_issued("2026-11-02T09:30:00Z"))
            .expect("the newer manifest must be accepted");
        // A stale mirror (or an attacker) replays the older, still
        // validly signed manifest: its checksums verify, its signature
        // verifies — the floor is the only thing that refuses it.
        let error = check_and_record_floor(&path, &manifest_issued("2026-10-19T00:00:00Z"))
            .expect_err("a replayed older manifest must be refused");
        assert!(error.contains("older"), "unexpected error: {error}");
        assert!(error.contains("replayed"), "unexpected error: {error}");
        // The refusal must not move the floor.
        assert_eq!(
            read_floor(&path).expect("floor must still read"),
            parse_issued_unix("2026-11-02T09:30:00Z")
        );
    }

    #[test]
    fn corrupt_floor_state_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FLOOR_FILENAME);
        let manifest = manifest_issued("2026-10-19T00:00:00Z");
        for corrupt in ["garbage", "", "  \n", "1792368000.5", "-42", "0x10"] {
            std::fs::write(&path, corrupt).expect("write corrupt floor");
            let error = check_and_record_floor(&path, &manifest)
                .expect_err("a corrupt floor must refuse, never be ignored");
            assert!(
                error.contains("corrupt"),
                "content {corrupt:?}: unexpected error: {error}"
            );
            // The refusal names the recovery: delete to re-baseline.
            assert!(
                error.contains("delete"),
                "content {corrupt:?}: unexpected error: {error}"
            );
        }
        // And the documented recovery works: after deletion the next
        // valid manifest is accepted and records a fresh floor.
        std::fs::remove_file(&path).expect("delete corrupt floor");
        check_and_record_floor(&path, &manifest).expect("re-baselined floor must accept");
    }
}
