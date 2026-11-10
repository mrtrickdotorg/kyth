"""Behavioral contracts for build_files/scripts/check-base-pin-drift.sh.

CI floats to the registry's current digest for the pinned Fedora base tag
(build.yml resolves it fresh), while local builds use the digest recorded
in build_base/Dockerfile / _vars.just. The drift check is the mechanism
that keeps a stale pin from being silent. All registry interaction is
fixture-driven: KYTH_BASE_CURRENT_DIGEST injects the "current" digest and
KYTH_BASE_RESOLVER=none forces the unresolved path, so no test here
touches the network.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build_files" / "scripts" / "check-base-pin-drift.sh"

FAKE_DIGEST = "sha256:" + "0" * 64
OTHER_DIGEST = "sha256:" + "1" * 64


def _pinned_ref() -> tuple[str, str]:
    """(image, digest) from the real build_base/Dockerfile ARG line."""
    dockerfile = (ROOT / "build_base" / "Dockerfile").read_text(encoding="utf-8")
    ref = next(
        line.split("=", 1)[1].strip()
        for line in dockerfile.splitlines()
        if line.startswith("ARG BASE_IMAGE=")
    )
    image, digest = ref.split("@", 1)
    return image, digest


def _run(env_extra: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # Isolate from any caller-provided knobs, then apply the fixture's.
    for key in (
        "KYTH_BASE_CURRENT_DIGEST",
        "KYTH_BASE_RESOLVER",
        "KYTH_BASE_DOCKERFILE",
        "KYTH_BASE_VARS_JUST",
        "GITHUB_ACTIONS",
    ):
        env.pop(key, None)
    env.update(env_extra)
    return subprocess.run(
        [str(SCRIPT), *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


class BasePinDriftBehavior(unittest.TestCase):
    def test_in_sync_when_registry_matches_the_pin(self):
        _, digest = _pinned_ref()
        result = _run({"KYTH_BASE_CURRENT_DIGEST": digest})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("in sync", result.stdout)
        self.assertIn(digest, result.stdout)

    def test_drift_warns_and_names_both_digests_and_both_files(self):
        image, digest = _pinned_ref()
        result = _run({"KYTH_BASE_CURRENT_DIGEST": FAKE_DIGEST})
        # Warn-only: drift must not fail the build that reports it.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DRIFT", result.stdout)
        self.assertIn(digest, result.stdout)
        self.assertIn(FAKE_DIGEST, result.stdout)
        # The re-pin instruction names the ref and both files to update.
        self.assertIn(f"{image}@{FAKE_DIGEST}", result.stdout)
        self.assertIn("build_base/Dockerfile", result.stdout)
        self.assertIn("_vars.just", result.stdout)

    def test_drift_fails_only_in_strict_mode(self):
        result = _run({"KYTH_BASE_CURRENT_DIGEST": FAKE_DIGEST}, "--strict")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("DRIFT", result.stdout)

    def test_unresolvable_registry_is_unknown_not_drift(self):
        result = _run({"KYTH_BASE_RESOLVER": "none"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("UNKNOWN", result.stdout)
        self.assertNotIn("DRIFT", result.stdout)
        # An outage is not drift even for a strict caller.
        strict = _run({"KYTH_BASE_RESOLVER": "none"}, "--strict")
        self.assertEqual(strict.returncode, 0, strict.stdout + strict.stderr)

    def test_malformed_current_digest_is_unknown_not_drift(self):
        result = _run({"KYTH_BASE_CURRENT_DIGEST": "not-a-digest"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("UNKNOWN", result.stdout)

    def test_split_pin_copies_are_reported(self):
        image, digest = _pinned_ref()
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / "Dockerfile"
            dockerfile.write_text(
                f"ARG BASE_IMAGE={image}@{digest}\n", encoding="utf-8"
            )
            vars_just = Path(tmp) / "_vars.just"
            vars_just.write_text(
                "export default_base_image := env(\"BASE_IMAGE\", "
                f'"{image}@{OTHER_DIGEST}")\n',
                encoding="utf-8",
            )
            env = {
                "KYTH_BASE_DOCKERFILE": str(dockerfile),
                "KYTH_BASE_VARS_JUST": str(vars_just),
                "KYTH_BASE_CURRENT_DIGEST": digest,
            }
            result = _run(env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("SPLIT", result.stdout)
            self.assertIn(digest, result.stdout)
            self.assertIn(OTHER_DIGEST, result.stdout)
            strict = _run(env, "--strict")
            self.assertEqual(strict.returncode, 1, strict.stdout + strict.stderr)

    def test_drift_is_a_github_actions_warning_annotation(self):
        result = _run(
            {"KYTH_BASE_CURRENT_DIGEST": FAKE_DIGEST, "GITHUB_ACTIONS": "true"}
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("::warning::", result.stdout)
        self.assertIn("DRIFT", result.stdout)


class BasePinDriftWiring(unittest.TestCase):
    def test_script_is_executable(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK), f"{SCRIPT} is not executable")

    def test_local_build_base_recipe_runs_the_check(self):
        build_just = (ROOT / "build.just").read_text(encoding="utf-8")
        recipe = build_just.split("build-base", 1)[1].split("\nbuild:", 1)[0]
        self.assertIn("check-base-pin-drift.sh", recipe)
        # Warn-only wiring: the check must never fail a local build.
        self.assertIn("check-base-pin-drift.sh || true", recipe)

    def test_ci_resolve_step_reports_drift_with_its_resolved_digest(self):
        build = (ROOT / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        step = build.split("- name: Resolve upstream base image digest", 1)[1].split(
            "- name: Build base image", 1
        )[0]
        self.assertIn("check-base-pin-drift.sh", step)
        # CI feeds the digest it already resolved; the script must not
        # re-resolve (and disagree with) the digest the build will use.
        self.assertIn('KYTH_BASE_CURRENT_DIGEST="${DIGEST}"', step)


if __name__ == "__main__":
    unittest.main()
