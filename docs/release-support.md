# Release Support

KythOS publishes a stable channel and a testing channel.

## Channels

| Channel | Tag | Support expectation |
| --- | --- | --- |
| Stable | `latest` | Supported for daily use. Security fixes and important regressions are prioritized here. |
| Testing | `testing` | Development preview. May contain incomplete features or regressions. |

## Update Model

KythOS uses atomic `bootc` deployments. Updates are staged before reboot and the
previous deployment remains available from the boot menu. This means a bad
update should usually be recoverable without reinstalling.

## Security Fixes

Security fixes are provided for the current stable channel. Testing receives
fixes as part of normal development and may receive them before stable while a
change is being validated.

## End of Support

KythOS does not maintain long-term old release lines. Channel releases move
forward. Users who need security fixes should update to the current stable
channel unless a specific advisory says otherwise.

## Immutable vs. Channel Artifacts

Every publish produces **two** artifact sets per channel **per ISO variant** (live and offline):

| Kind | GitHub release tag | R2 ISO name | Mutability |
| --- | --- | --- | --- |
| Immutable | `iso-{testing,latest}-{release_id}` (e.g. `iso-testing-20260918-abcdef01-42-1`) | `kyth-live-{tag}-{release_id}.iso` | Never overwritten in place; on R2, retention keeps only the newest 5 build sets per variant and channel |
| Channel pointer | `iso-testing` / `iso-latest` | `kyth-live-testing.iso` / `kyth-live-latest.iso` | Overwritten in place on every publish |
| Offline immutable | `iso-offline-{testing,latest}-{release_id}` | `kyth-offline-{tag}-{release_id}.iso` | Never overwritten in place; same retention as live |
| Offline channel pointer | `iso-offline-testing` / `iso-offline-latest` | `kyth-offline-testing.iso` / `kyth-offline-latest.iso` | Overwritten in place on every publish |

The offline ISO boots a minimal installer session (no desktop preview) and carries the same signed image embedded, so it installs with no network. The live ISO is the smaller download and previews the full desktop, but downloads the image during setup.

The channel pointer is what users download. The immutable set is the
audit trail and the rollback source — with one boundary: after every
publish, R2 retention (`build_files/scripts/r2_retention.py`) keeps
only the **newest 5 immutable build sets per variant and channel** and deletes
older ones, so a rollback target more than five builds back may no
longer exist on R2. (The immutable GitHub releases are not purged.)
Container images follow the same split: the build job publishes only
immutable version tags — `ghcr.io/mrtrickdotorg/kyth:<version>`, where
`<version>` is `<channel>.<yyyymmdd>.<run>.<attempt>.<sha8>` — plus an
`image-<version-with-dashes>` changelog release per version. The moving `:latest` /
`:testing` tags are promoted afterwards by the supply-chain publish
job, digest-exact, only after the image is signed and its changelog
release exists.

## Channel Rollback

Use this when a published channel is bad and the fix is to repoint the
channel at the previous immutable build — not to ship a new one.
On-device recovery (`bootc rollback`) is separate and stays available
regardless; this procedure repairs the *published channel* so new
installs and upgrades stop picking up the bad build.

> Old timestamped artifacts are not patched: a rollback also rolls back
> any security fixes shipped after the previous immutable build. Treat a
> rolled-back channel as a stopgap and roll forward with a fixed build as
> soon as one is ready.

Prerequisites: `gh` authenticated against this repo, and R2 credentials
(`R2_ENDPOINT_URL` or `R2_ACCOUNT_ID`, `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`) for the `kyth-releases` bucket.

1. Identify the bad and previous immutable tags (example: `testing`):

```bash
TAG=testing
gh release list --limit 30 --json tagName \
  -q '.[] | .tagName | select(startswith("iso-'"${TAG}"'-"))'
```

Pick `BAD` (current) and `PREV` (the last known-good immutable tag).
On R2, retention keeps only the newest 5 build sets per channel, so
`PREV` must be within that window for step 3 to find its objects.

2. Fetch the previous immutable ISO and verify it before promoting:

```bash
gh release download "${PREV}" \
  -p 'kyth-live-'"${TAG}"'-*.iso' \
  -p 'kyth-live-'"${TAG}"'-*.iso-CHECKSUM'
sha256sum --check --strict kyth-live-"${TAG}"-*.iso-CHECKSUM
```

The check must pass. For the strongest guarantee, also verify the
Cosign signature/bundle attached to the `${PREV}` release before use.

3. Repoint the R2 channel files at the previous immutable build. The
immutable R2 objects are never overwritten, so copy them over the
channel names (plus `-CHECKSUM`, `.sig`, `.bundle`, `.intoto.jsonl`,
`.json` sidecars):

```bash
IMM=kyth-live-"${TAG}"-...iso   # full previous immutable basename from step 1
CHAN=kyth-live-"${TAG}".iso
for suffix in '' -CHECKSUM .sig .bundle .intoto.jsonl .json; do
  aws s3 cp "s3://kyth-releases/${IMM}${suffix}" \
    "s3://kyth-releases/${CHAN}${suffix}" \
    --endpoint-url "${R2_ENDPOINT_URL}"
done
```

4. Repoint the channel GitHub release at the previous immutable build.
The channel release is refreshed in place by design:
`build_files/scripts/publish-release.py` converges via view → edit and
never deletes it, so the moving tag never 404s mid-rollback. The
supported path is to re-run the publish step with the previous build's
artifacts, which refreshes the target, notes, and channel sidecar
assets together. The manual minimum is the same edit by hand:

```bash
PREV_SHA="$(gh release view "${PREV}" --json targetCommitish -q .targetCommitish)"
gh release edit "iso-${TAG}" --target "${PREV_SHA}" \
  --title "Kyth Live ISO - ${TAG} (rollback to ${PREV})" \
  --notes "Channel rolled back to immutable release ${PREV}. See that release for the changelog, checksum, and signatures."
```

5. Confirm the channel serves the rolled-back bytes:

```bash
curl -fsSL -o /tmp/chan.iso "https://pub-9a3cc72972ea44c4ae7504ee7cda1fa6.r2.dev/${CHAN}"
curl -fsSL -o /tmp/chan.iso-CHECKSUM "https://pub-9a3cc72972ea44c4ae7504ee7cda1fa6.r2.dev/${CHAN}-CHECKSUM"
(cd /tmp && sha256sum --check --strict chan.iso-CHECKSUM)
```

(The public download base URL is single-sourced from
`R2_PUBLIC_BASE_URL` in `build_files/scripts/release_identity.py` —
update it there, not in copies.)

Container image rollback follows the same repoint logic: point the
channel tag back at the previous verified digest, exactly as the
supply-chain publish job promotes it — digest-exact, not a copy
(e.g. `oras tag "ghcr.io/mrtrickdotorg/kyth@${PREV_DIGEST}" "${TAG}"`) —
then verify with `cosign verify` and the pinned digest before
announcing. The previous digest for an ISO release is recorded in its
release notes as `Source image digest`; for an image release it is the
`Image:` line of the last good `image-*` release body. Installed
systems do not need to wait for either repoint: switch directly to the
previous immutable ref (`sudo bootc switch
ghcr.io/mrtrickdotorg/kyth:<previous-version>`, or the
`@sha256:<digest>` ref), and use the boot menu / `bootc rollback` when
a deployment merely fails to boot.

## Verifying a Download

Every ISO ships with a `-CHECKSUM` sidecar next to it on R2 and on its
immutable GitHub release. Verify before writing to USB:

```bash
curl -fsSL -O https://pub-9a3cc72972ea44c4ae7504ee7cda1fa6.r2.dev/kyth-live-latest.iso
curl -fsSL -O https://pub-9a3cc72972ea44c4ae7504ee7cda1fa6.r2.dev/kyth-live-latest.iso-CHECKSUM
sha256sum --check --strict kyth-live-latest.iso-CHECKSUM
```

A passing check confirms the bytes match the published build. The
`.sig` / `.bundle` / `.intoto.jsonl` attachments on the immutable
GitHub release additionally bind the ISO to its build provenance via
Cosign and GitHub attestation — check those when the download source
is untrusted.

## Reinstall vs. Upgrade

Most changes should be delivered through `bootc upgrade`. A reinstall should be
required only for installer-specific defects, disk layout choices, or documented
breaking changes that cannot be safely migrated in place.


## Switching an installed system to the destination registry

The supported image references are `ghcr.io/mrtrickdotorg/kyth:latest`,
`ghcr.io/mrtrickdotorg/kyth:testing`,
`ghcr.io/mrtrickdotorg/kyth:latest-cachy`, and
`ghcr.io/mrtrickdotorg/kyth:testing-cachy`. Existing deployments keep tracking
their configured image reference; updates do not silently change the host's
bootc origin.

Before switching, inspect the effective signature policy (including any
`/etc/containers/policy.json` override) and confirm it permits the destination
image's signatures. Record `sudo bootc status` before the change. Explicitly
opt in by selecting the matching channel and kernel flavor, for example:

```bash
sudo bootc switch ghcr.io/mrtrickdotorg/kyth:testing
sudo bootc status
sudo systemctl reboot
```

After reboot, run `sudo bootc status` again and verify the active deployment and
image match the intended channel. Do not remove the previous deployment until
this check succeeds. If the new deployment fails to boot or is unhealthy, use
the boot menu to select the previous deployment; once booted, `sudo bootc
rollback` restores the prior deployment as the rollback target. Then reboot and
verify status. Switching is opt-in; there is no automatic origin migration.

## Destination-testing preflight (manual, non-publishing)

Destination-built publication is **not enabled**. The only destination path
released today is the unchanged-stable maintenance copy in
`.github/workflows/supply-chain.yml` (`migrate_legacy_stable`), documented
above.

A manual `Build container image` dispatch with `destination_testing: true` runs
a read-only preflight and then fails closed; it never builds, signs, or
publishes an image and does not promote a tag:

- Only `workflow_dispatch` on `testing` at the current tip qualifies, and the
  exact SHA must already have a successful `Validation` run from the `push`
  event on `.github/workflows/validation.yml`. `skip_validation: true` is
  rejected in this mode.
- The job holds `actions: read` and `contents: read` only, and derives the
  repository, ref, SHA, run ID, and run attempt from trusted workflow context
  and the GitHub API rather than from dispatch inputs.
- Identity checks live in `build_files/scripts/destination_testing_policy.py`:
  they fix the source repository, the `testing`/`fedora` and
  `testing-cachy`/`cachy` channel plan, and the
  `destination-{base,raw,candidate}-<channel>-<run>-<attempt>-<flavor>` tags.
  The preflight computes those plans and exits non-zero on any mismatch.

Anyone changing the source repository, the destination image, or the channel
plan must update that policy module and its tests together; `validate.sh`
runs them as a fast gate.
