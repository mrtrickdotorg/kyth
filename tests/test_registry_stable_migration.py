import importlib.util
import os
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class StableMigrationContract(unittest.TestCase):
    def run_cli(self, **overrides):
        env = os.environ.copy()
        env.update(dict(
            MIGRATE_LEGACY_STABLE="true", GITHUB_REPOSITORY="mrtrickdotorg/kyth",
            GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF="refs/heads/testing",
            ORIGINAL_EVENT="", SOURCE_TAG="latest", SOURCE_SHA="a" * 40,
            MAIN_SHA="a" * 40, SOURCE_DIGEST="sha256:" + "b" * 64,
            LEGACY_DIGEST="sha256:" + "b" * 64,
        ))
        for key, value in overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return subprocess.run(
            [sys.executable, str(ROOT / ".github/scripts/validate-stable-migration.py")],
            env=env, text=True, capture_output=True, check=False,
        )

    def test_cli_accepts_valid_environment(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"tag": "latest"', result.stdout)

    def test_cli_rejects_missing_environment(self):
        result = self.run_cli(MAIN_SHA=None)
        self.assertNotEqual(result.returncode, 0)

    def test_cli_rejects_malformed_boolean(self):
        result = self.run_cli(MIGRATE_LEGACY_STABLE="yes")
        self.assertNotEqual(result.returncode, 0)

    def test_cli_rejects_malformed_digest(self):
        result = self.run_cli(SOURCE_DIGEST="sha256:bad")
        self.assertNotEqual(result.returncode, 0)

    def test_cli_rejects_nonzero_context(self):
        result = self.run_cli(GITHUB_REF="refs/heads/main")
        self.assertNotEqual(result.returncode, 0)

    def module(self):
        spec = importlib.util.spec_from_file_location(
            "migration", ROOT / ".github/scripts/validate-stable-migration.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def context(self):
        return dict(
            enabled=True, repository="mrtrickdotorg/kyth", event="workflow_dispatch",
            ref="refs/heads/testing", original_event="", tag="latest",
            source_sha="a" * 40, main_sha="a" * 40,
            source_digest="sha256:" + "b" * 64,
            legacy_digest="sha256:" + "b" * 64,
        )

    def test_allowed_context_preserves_stable_channel_and_digest(self):
        module = self.module()
        for tag in ("latest", "latest-cachy"):
            with self.subTest(tag=tag):
                self.assertTrue(module.validate(dict(self.context(), tag=tag)))

    def test_rejects_other_contexts_and_malformed_identifiers(self):
        module = self.module()
        for key, value in (
            ("enabled", False), ("enabled", "true"),
            ("repository", "kyth-os/kyth"), ("event", "push"),
            ("ref", "refs/heads/main"), ("original_event", "schedule"),
            ("tag", "testing"), ("tag", "testing-cachy"),
            ("source_sha", "c" * 40), ("source_sha", "main"),
            ("source_digest", "sha256:" + "d" * 64),
            ("source_digest", "sha256:bad"),
            ("main_sha", "a" * 39), ("legacy_digest", "sha256:bad"),
        ):
            with self.subTest(key=key, value=value):
                self.assertFalse(module.validate(dict(self.context(), **{key: value})))
        for key in self.context():
            case = self.context()
            del case[key]
            self.assertFalse(module.validate(case))

    def test_workflow_is_separate_gated_and_opt_in(self):
        text = (ROOT / ".github/workflows/supply-chain.yml").read_text()
        self.assertIn("migrate_legacy_stable:", text)
        self.assertIn("inputs.migrate_legacy_stable != true", text)
        job = text.split("  migrate_stable:\n", 1)[1]
        for token in (
            "inputs.migrate_legacy_stable == true", "environment: stable-release",
            "validate-stable-migration.py", "--bundle-from-oci",
            "--source-ref refs/heads/main", "--deny-self-hosted-runners",
            "--preserve-digests", "--recursive", "--policy",
            "sigstoreSigned", "matchRepository", "--src-no-creds",
        ):
            self.assertIn(token, job)
        self.assertLess(job.index("Verify legacy build provenance"), job.index("Copy verified immutable image"))
        self.assertLess(job.index("Verify destination signatures and policy"), job.index("Promote unchanged stable digest"))
        self.assertNotIn("original_event == 'schedule'", job)
        self.assertNotIn("dispatch-workflow", job)
        self.assertNotIn("gh release", job)
        self.assertNotIn("insecureAcceptAnything", job)


if __name__ == "__main__":
    unittest.main()
