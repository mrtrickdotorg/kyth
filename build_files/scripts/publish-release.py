#!/usr/bin/env python3
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

from release_identity import SUPPORTED_CHANNELS, r2_download_url

def run_command(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    print(f"Running: {' '.join(args)}")
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        # Surface the tool's own output before failing: a bare
        # CalledProcessError hides WHY gh failed (e.g. "release already
        # exists" when a racing publish created it first).
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        if check:
            raise subprocess.CalledProcessError(result.returncode, args)
    return result

def artifact_paths(source_dir: Path, basename: str) -> list[Path]:
    """The ISO and the five sidecars every publish attaches for it."""
    base = source_dir / basename
    return [
        base,
        Path(f"{base}-CHECKSUM"),
        Path(f"{base}.sig"),
        Path(f"{base}.bundle"),
        Path(f"{base}.intoto.jsonl"),
        Path(f"{base}.json"),
    ]

def sha256_hexdigest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def preflight(args: argparse.Namespace) -> tuple[int, str]:
    """Validate the publish inputs before any mutation.

    Returns (0, changelog_content) when the inputs are publishable, or
    (1, "") after printing the problem. Publishing used to discover bad
    inputs halfway through — a garbage source tag silently became a
    --latest stable release, an unreadable changelog published empty
    notes, and nothing checked the artifacts or their checksums before
    the first gh call mutated release state.
    """
    if args.source_tag not in SUPPORTED_CHANNELS:
        print(
            f"error: unsupported source tag {args.source_tag!r}: "
            f"expected one of {', '.join(sorted(SUPPORTED_CHANNELS))}",
            file=sys.stderr,
        )
        return 1, ""

    try:
        changelog_content = args.iso_changelog.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"error: cannot read ISO changelog {args.iso_changelog}: {exc}", file=sys.stderr)
        return 1, ""
    if not changelog_content.strip():
        print(f"error: ISO changelog {args.iso_changelog} is empty", file=sys.stderr)
        return 1, ""

    # The versioned (immutable) basename carries the ISO itself plus its
    # five sidecars. The channel basename never exists as an ISO file:
    # the channel is a pointer — the R2 upload step copies the versioned
    # ISO under the channel key — so only its five sidecars are staged
    # (the build job writes the channel -CHECKSUM, the metadata step
    # copies .sig/.bundle/.intoto.jsonl, the metadata generator writes
    # .json). Requiring the channel ISO file here failed every publish:
    # it is absent by design.
    required = list(artifact_paths(args.source_dir, args.iso_basename))
    if args.channel_basename != args.iso_basename:
        required += artifact_paths(args.source_dir, args.channel_basename)[1:]
    for path in dict.fromkeys(required):
        if not path.is_file() or path.stat().st_size == 0:
            print(f"error: expected release artifact missing or empty: {path}", file=sys.stderr)
            return 1, ""

    # Both CHECKSUM files record the versioned ISO's digest (the build
    # job writes the channel one under the channel filename), so both
    # verify against the one ISO file that exists.
    iso_path = args.source_dir / args.iso_basename
    actual = sha256_hexdigest(iso_path)
    for basename in dict.fromkeys((args.iso_basename, args.channel_basename)):
        checksum_path = Path(f"{args.source_dir / basename}-CHECKSUM")
        try:
            recorded = checksum_path.read_text(encoding="utf-8").split()
        except (OSError, ValueError) as exc:
            print(f"error: cannot read checksum file {checksum_path}: {exc}", file=sys.stderr)
            return 1, ""
        if not recorded or recorded[0].lower() != actual:
            print(
                f"error: checksum mismatch for {iso_path}: {checksum_path} records "
                f"{recorded[0] if recorded else '<nothing>'}, computed {actual}",
                file=sys.stderr,
            )
            return 1, ""

    return 0, changelog_content

def main() -> int:
    parser = argparse.ArgumentParser(description="Create GitHub Releases and upload artifacts.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--channel-tag", required=True)
    parser.add_argument("--immutable-tag", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--attestation-url", required=True)
    parser.add_argument("--iso-basename", required=True)
    parser.add_argument("--channel-basename", required=True)
    parser.add_argument("--iso-changelog", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    # Preflight: refuse bad inputs before the first gh invocation.
    preflight_rc, changelog_content = preflight(args)
    if preflight_rc != 0:
        return preflight_rc

    # Form titles and options. Preflight has already pinned source_tag to
    # SUPPORTED_CHANNELS, so the else branch is exactly the stable channel.
    if args.source_tag == "testing":
        channel_title = "Kyth Live ISO - Testing"
        immutable_title = f"Kyth Live ISO - Testing - {args.release_id}"
        prerelease = True
        latest = False
    else:
        channel_title = "Kyth Live ISO - Stable"
        immutable_title = f"Kyth Live ISO - Stable - {args.release_id}"
        prerelease = False
        latest = True

    immutable_iso_url = r2_download_url(args.iso_basename)
    channel_iso_url = r2_download_url(args.channel_basename)
    immutable_release_url = f"https://github.com/{args.repo}/releases/tag/{args.immutable_tag}"

    # 1. Generate Immutable Release Notes
    immutable_notes_lines = [
        f"Permanent KythOS ISO build from **{args.source_tag}**.",
        "",
        changelog_content.strip(),
        "",
        "---",
        f"**[Download immutable ISO]({immutable_iso_url})** | [Checksum]({immutable_iso_url}-CHECKSUM)",
        "",
        f"- Source commit: **{args.source_sha}**",
        f"- Source image digest: **{args.source_digest}**",
        f"- Workflow run: https://github.com/{args.repo}/actions/runs/{args.run_id}",
        f"- Build provenance: {args.attestation_url}",
        "",
        "The checksum, Cosign signature and bundle, metadata, and GitHub build provenance are attached to this release."
    ]
    immutable_notes_file = Path("immutable_notes.md")
    immutable_notes_file.write_text("\n".join(immutable_notes_lines).strip() + "\n", encoding="utf-8")

    # Create Immutable Release
    create_imm_args = ["gh", "release", "create", args.immutable_tag,
                       "--target", args.source_sha,
                       "--title", immutable_title,
                       "--notes-file", str(immutable_notes_file)]
    if prerelease:
        create_imm_args.append("--prerelease")

    # Create the immutable release — or refresh it if one already exists.
    # This workflow cancels in progress, so a superseded run's publish job
    # can create the release moments before this run reaches the same step;
    # the publish must converge on the existing release, not die on
    # "already exists" (the loser of that race failed ISO publish on
    # 2026-10-12 and the winner's release had to be cleaned up by hand).
    if run_command(["gh", "release", "view", args.immutable_tag], check=False).returncode == 0:
        edit_imm_args = ["gh", "release", "edit", args.immutable_tag,
                         "--title", immutable_title,
                         "--notes-file", str(immutable_notes_file)]
        if prerelease:
            edit_imm_args.append("--prerelease")
        run_command(edit_imm_args)
    else:
        run_command(create_imm_args)

    # Upload Immutable Artifacts
    iso_path = args.source_dir / args.iso_basename
    upload_imm_files = [
        f"{iso_path}-CHECKSUM",
        f"{iso_path}.sig",
        f"{iso_path}.bundle",
        f"{iso_path}.intoto.jsonl",
        f"{iso_path}.json"
    ]
    run_command(["gh", "release", "upload", args.immutable_tag, "--clobber"] + upload_imm_files)

    # 2. Generate Channel Release Notes
    channel_notes_lines = [
        f"This is the moving **{args.source_tag}** channel pointer.",
        "",
        changelog_content.strip(),
        "",
        "---",
        f"**[Download current ISO]({channel_iso_url})** | [Checksum]({channel_iso_url}-CHECKSUM)",
        "",
        f"Current immutable release: [{args.immutable_tag}]({immutable_release_url})",
        "",
        f"- Source commit: **{args.source_sha}**",
        f"- Source image digest: **{args.source_digest}**",
        f"- Build provenance: {args.attestation_url}"
    ]
    channel_notes_file = Path("channel_notes.md")
    channel_notes_file.write_text("\n".join(channel_notes_lines).strip() + "\n", encoding="utf-8")

    # Create the channel release — or refresh it if one already exists,
    # mirroring the immutable release above. This used to delete and
    # recreate the channel release on every publish, which left a window
    # where the moving tag 404'd and discarded the release's state;
    # converging via view -> edit/create has neither problem.
    create_chan_args = ["gh", "release", "create", args.channel_tag,
                        "--target", args.source_sha,
                        "--title", channel_title,
                        "--notes-file", str(channel_notes_file)]
    if prerelease:
        create_chan_args.append("--prerelease")
    if latest:
        create_chan_args.append("--latest")

    if run_command(["gh", "release", "view", args.channel_tag], check=False).returncode == 0:
        edit_chan_args = ["gh", "release", "edit", args.channel_tag,
                          "--title", channel_title,
                          "--notes-file", str(channel_notes_file)]
        if prerelease:
            edit_chan_args.append("--prerelease")
        if latest:
            # gh release edit accepts --latest ("Explicitly mark the
            # release as Latest"), so a refresh keeps the stable channel
            # marked exactly as a fresh create would.
            edit_chan_args.append("--latest")
        run_command(edit_chan_args)
    else:
        run_command(create_chan_args)

    # Upload Channel Artifacts
    channel_path = args.source_dir / args.channel_basename
    upload_chan_files = [
        f"{channel_path}-CHECKSUM",
        f"{channel_path}.sig",
        f"{channel_path}.bundle",
        f"{channel_path}.intoto.jsonl",
        f"{channel_path}.json"
    ]
    run_command(["gh", "release", "upload", args.channel_tag, "--clobber"] + upload_chan_files)

    # Clean up temp files
    try:
        immutable_notes_file.unlink()
        channel_notes_file.unlink()
    except OSError:
        pass

    return 0

if __name__ == "__main__":
    sys.exit(main())
