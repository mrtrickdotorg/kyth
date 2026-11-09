"""ISO publish (publish-release.py) must be idempotent and preflighted.

build-live-iso cancels in progress, so a superseded run's publish job can
create the immutable release moments before the replacement run reaches
the same step. The replacement used to die on `gh release create`
("already exists") and take the whole ISO publish down with it
(2026-10-12). These tests drive main() with a recording run_command
stand-in and pin the convergent behavior.

They also pin the preflight: a source tag outside the supported channels,
a missing/empty artifact, a checksum that does not match its ISO, or an
unreadable/empty changelog must fail before a single gh call is made —
publishing used to proceed past all of those and mutate release state.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "build_files/scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("publish_release", SCRIPTS / "publish-release.py")
assert SPEC and SPEC.loader
publish_release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publish_release
SPEC.loader.exec_module(publish_release)

ISO_BASENAME = "kyth-live-testing.iso"
CHANNEL_BASENAME = "kyth-live-testing.iso"
IMMUTABLE_TAG = "iso-testing-20261012-abcdef0-948-1"
CHANNEL_TAG = "iso-testing"
ISO_BYTES = b"kyth live iso test payload\n"


def _completed(returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr="")


def write_artifacts(source_dir: Path, basenames: tuple[str, ...]) -> None:
    """Write a production-shaped artifact set: ISO, sha256sum-format
    -CHECKSUM (as build-live-iso generates it), and the four other
    sidecars, all non-empty."""
    for basename in dict.fromkeys(basenames):
        iso = source_dir / basename
        iso.write_bytes(ISO_BYTES)
        digest = hashlib.sha256(ISO_BYTES).hexdigest()
        Path(f"{iso}-CHECKSUM").write_text(f"{digest}  {basename}\n", encoding="utf-8")
        for suffix in (".sig", ".bundle", ".intoto.jsonl", ".json"):
            Path(f"{iso}{suffix}").write_text("test\n", encoding="utf-8")


class RecordingRunner:
    """Stands in for run_command; records argv, answers `release view`
    per tag so immutable and channel existence are independent."""

    def __init__(self, immutable_exists: bool, channel_exists: bool = False):
        self.immutable_exists = immutable_exists
        self.channel_exists = channel_exists
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        self.calls.append(list(args))
        if args[:3] == ["gh", "release", "view"]:
            exists = {
                IMMUTABLE_TAG: self.immutable_exists,
                CHANNEL_TAG: self.channel_exists,
            }
            return _completed(0 if exists.get(args[3], False) else 1)
        return _completed(0)

    def find(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]


def invoke_main(
    runner: RecordingRunner,
    *,
    source_tag: str = "testing",
    changelog_text: str | None = "notes",
    setup: Callable[[Path], None] | None = None,
) -> int:
    """Run main() against a valid artifact fixture in a temp dir.

    `setup` runs after the fixture is written so a test can break exactly
    one input (delete a sidecar, corrupt a checksum, ...). A changelog of
    None leaves the changelog path nonexistent.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        changelog = tmp_path / "changelog.md"
        if changelog_text is not None:
            changelog.write_text(changelog_text, encoding="utf-8")
        write_artifacts(tmp_path, (ISO_BASENAME, CHANNEL_BASENAME))
        if setup is not None:
            setup(tmp_path)
        argv = [
            "publish-release.py",
            "--repo", "kyth-os/kyth",
            "--source-tag", source_tag,
            "--channel-tag", CHANNEL_TAG,
            "--immutable-tag", IMMUTABLE_TAG,
            "--release-id", "20261012-abcdef0-948-1",
            "--source-sha", "a" * 40,
            "--source-digest", "sha256:" + "b" * 64,
            "--attestation-url", "",
            "--iso-basename", ISO_BASENAME,
            "--channel-basename", CHANNEL_BASENAME,
            "--iso-changelog", str(changelog),
            "--source-dir", str(tmp_path),
            "--run-id", "123",
        ]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            publish_release, "run_command", runner
        ), mock.patch.object(Path, "cwd", return_value=tmp_path):
            # Notes files are written next to the CWD; run inside tmp.
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                return publish_release.main()
            finally:
                os.chdir(old_cwd)


class IsoPublishIdempotencyTests(unittest.TestCase):
    def run_main(self, runner: RecordingRunner) -> None:
        self.assertEqual(invoke_main(runner), 0)

    def test_existing_immutable_release_is_edited_not_recreated(self):
        runner = RecordingRunner(immutable_exists=True)
        self.run_main(runner)
        self.assertEqual(runner.find("gh", "release", "create", IMMUTABLE_TAG), [])
        edits = runner.find("gh", "release", "edit", IMMUTABLE_TAG)
        self.assertEqual(len(edits), 1)
        self.assertIn("--notes-file", edits[0])

    def test_missing_immutable_release_is_created(self):
        runner = RecordingRunner(immutable_exists=False)
        self.run_main(runner)
        creates = runner.find("gh", "release", "create", IMMUTABLE_TAG)
        self.assertEqual(len(creates), 1)
        self.assertEqual(runner.find("gh", "release", "edit"), [])

    def test_immutable_upload_clobbers_so_reruns_converge(self):
        runner = RecordingRunner(immutable_exists=True)
        self.run_main(runner)
        uploads = runner.find("gh", "release", "upload", IMMUTABLE_TAG)
        self.assertEqual(len(uploads), 1)
        self.assertIn("--clobber", uploads[0])

    def test_existing_channel_release_is_edited_never_deleted(self):
        runner = RecordingRunner(immutable_exists=True, channel_exists=True)
        self.assertEqual(invoke_main(runner, source_tag="latest"), 0)
        # No execution path may delete a release: the old delete/recreate
        # left a 404 window on the moving channel tag.
        self.assertEqual(runner.find("gh", "release", "delete"), [])
        self.assertEqual(runner.find("gh", "release", "create", CHANNEL_TAG), [])
        edits = runner.find("gh", "release", "edit", CHANNEL_TAG)
        self.assertEqual(len(edits), 1)
        self.assertIn("--notes-file", edits[0])
        # A stable refresh keeps the release marked Latest, as create did.
        self.assertIn("--latest", edits[0])


class IsoPublishPreflightTests(unittest.TestCase):
    def assert_fails_before_any_gh_call(self, runner: RecordingRunner, **kwargs) -> None:
        self.assertNotEqual(invoke_main(runner, **kwargs), 0)
        self.assertEqual(runner.calls, [])

    def test_unknown_source_tag_fails_before_any_gh_call(self):
        runner = RecordingRunner(immutable_exists=False)
        self.assert_fails_before_any_gh_call(runner, source_tag="nightly")

    def test_missing_sidecar_fails_before_any_gh_call(self):
        def remove_signature(tmp_path: Path) -> None:
            Path(tmp_path / f"{ISO_BASENAME}.sig").unlink()

        runner = RecordingRunner(immutable_exists=False)
        self.assert_fails_before_any_gh_call(runner, setup=remove_signature)

    def test_checksum_mismatch_fails_before_any_gh_call(self):
        def corrupt_checksum(tmp_path: Path) -> None:
            wrong = hashlib.sha256(b"not the iso").hexdigest()
            Path(tmp_path / f"{ISO_BASENAME}-CHECKSUM").write_text(
                f"{wrong}  {ISO_BASENAME}\n", encoding="utf-8"
            )

        runner = RecordingRunner(immutable_exists=False)
        self.assert_fails_before_any_gh_call(runner, setup=corrupt_checksum)

    def test_empty_changelog_fails_before_any_gh_call(self):
        runner = RecordingRunner(immutable_exists=False)
        self.assert_fails_before_any_gh_call(runner, changelog_text="  \n")

    def test_unreadable_changelog_fails_before_any_gh_call(self):
        runner = RecordingRunner(immutable_exists=False)
        self.assert_fails_before_any_gh_call(runner, changelog_text=None)


class RunCommandDiagnosticsTests(unittest.TestCase):
    def test_failure_surfaces_gh_stderr_before_raising(self):
        fake = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="release already exists"
        )
        with mock.patch.object(publish_release.subprocess, "run", return_value=fake):
            with self.assertRaises(subprocess.CalledProcessError):
                publish_release.run_command(["gh", "release", "create", "x"])

    def test_unchecked_failure_returns_result(self):
        fake = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="nope")
        with mock.patch.object(publish_release.subprocess, "run", return_value=fake):
            result = publish_release.run_command(["gh", "release", "view", "x"], check=False)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
